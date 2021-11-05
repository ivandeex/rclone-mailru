// Package icloud provides an interface to the Apple iCloud Drive storage.
package icloud

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/operations"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/file"
	"github.com/rclone/rclone/lib/readers"

	"github.com/ivandeex/go-icloud/icloud"
	"github.com/sirupsen/logrus"
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "icloud",
		Description: "Apple iCloud Drive",
		NewFs:       NewFs,
		Options: []fs.Option{
			{
				Name:     "username",
				Help:     "User's AppleID",
				Required: true,
			},
			{
				Name:     "password",
				Help:     "Password",
				Required: true,
			},
			{
				Name:     "user_agent",
				Help:     "User Agent to use when sending requests",
				Default:  "",
				Advanced: true,
			},
			{
				Name:     config.ConfigEncoding,
				Help:     config.ConfigEncodingHelp,
				Default:  encoder.EncodeSlash | encoder.EncodeInvalidUtf8,
				Advanced: true,
			},
		},
	})
}

// Options configured for this backend
type Options struct {
	Username  string `config:"username"`
	Password  string `config:"password"`
	UserAgent string `config:"user_agent"`

	Enc encoder.MultiEncoder `config:"encoding"`
}

// Fs represents a remote box
type Fs struct {
	name     string       // name of this remote
	root     string       // the path we are working on
	opt      *Options     // parsed options
	features *fs.Features // optional features
	api      *icloud.Client
	drive    *icloud.DriveService
	rootNode *icloud.DriveNode
}

var apiLogFormat logrus.Formatter

func setClientLogging(ctx context.Context) {
	ci := fs.GetConfig(ctx)
	dump := ci.Dump&(fs.DumpHeaders|fs.DumpBodies|fs.DumpRequests|fs.DumpResponses) > 0
	trace := false
	switch ci.LogLevel {
	case fs.LogLevelDebug:
		logrus.SetLevel(logrus.DebugLevel)
		trace = true
	case fs.LogLevelInfo:
		logrus.SetLevel(logrus.InfoLevel)
	case fs.LogLevelWarning, fs.LogLevelNotice:
		logrus.SetLevel(logrus.WarnLevel)
	default:
		logrus.SetLevel(logrus.ErrorLevel)
	}
	if trace && dump {
		if apiLogFormat == nil {
			apiLogFormat = &logrus.TextFormatter{
				ForceColors:     true,
				DisableQuote:    true,
				FullTimestamp:   true,
				TimestampFormat: "06-01-02 15:04:05.000",
			}
		}
		logrus.SetFormatter(apiLogFormat)
		logrus.SetLevel(logrus.TraceLevel)
		icloud.Debug = true
	}
}

func (f *Fs) connect(ctx context.Context) (err error) {
	dataDir := filepath.Join(config.GetCacheDir(), "icloud")
	if err = file.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("%s: cannot setup data directory: %w", dataDir, err)
	}

	setClientLogging(ctx)
	if f.opt.Username == "" || f.opt.Password == "" {
		return fmt.Errorf("you must provide username and password")
	}

	f.api, err = icloud.NewClient(f.opt.Username, f.opt.Password, dataDir, f.opt.UserAgent)
	if err == nil {
		err = f.authorize()
	}
	if err != nil {
		err = fmt.Errorf("icloud login failed: %w", err)
	}
	return err
}

// authorize current session
func (f *Fs) authorize() error {
	api := f.api
	if err := api.Authenticate(false, ""); err != nil {
		return err
	}
	if api.Requires2SA() {
		fs.Logf(f, "Two-step authentication required.")
		devices, err := api.TrustedDevices()
		if err != nil {
			return err
		}
		fs.Logf(f, "Your trusted devices are: %#v", devices)
		dev := &devices[0]
		fs.Logf(f, "Sending verification code to the first device...")
		if err = api.SendVerificationCode(dev); err != nil {
			return err
		}
		code := icloud.ReadLine("Please enter validation code: ")
		if err = api.ValidateVerificationCode(dev, code); err != nil {
			return fmt.Errorf("failed to verify verification code: %w", err)
		}
	}
	if api.Requires2FA() {
		fs.Logf(f, "Two-factor authentication required.")
		code := icloud.ReadLine("Enter the code you received of one of your approved devices: ")
		if err := api.Validate2FACode(code); err != nil {
			return fmt.Errorf("failed to verify security code: %w", err)
		}
		if !api.IsTrustedSession() {
			fs.Infof(f, "Session is not trusted. Requesting trust...")
			if err := api.TrustSession(); err != nil {
				fs.Errorf(f, "Failed to request trust. You will likely be prompted for the code again in the coming weeks")
				return err
			}
		}
	}
	return nil
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := &Options{}
	if err := configstruct.Set(m, opt); err != nil {
		return nil, fmt.Errorf("cannot parse icloud options: %w", err)
	}

	f := &Fs{
		name: name,
		opt:  opt,
	}

	err := f.connect(ctx)
	if err == nil {
		f.drive, err = icloud.NewDrive(f.api)
	}
	if err == nil {
		f.rootNode, err = f.drive.Root()
	}
	if err != nil {
		return nil, err
	}

	features := &fs.Features{
		CanHaveEmptyDirectories: true,
	}
	f.features = features.Fill(ctx, f)

	// Ensure root is a directory
	root = strings.Trim(root, "/")
	if root != "" {
		nodePath := f.toNodePath(root) // NB: f.root == "" at this point
		rootNode, err := f.getNode(nodePath)
		if err == nil && !rootNode.IsDir() {
			parent, _ := pathSplit(root)
			f.root = parent // FIXME Encode root
			return f, fs.ErrorIsFile
		}
	}
	f.root = root // FIXME Encode root
	return f, nil
}

// Name of the remote
func (f *Fs) Name() string { return f.name }

// Root of the remote
func (f *Fs) Root() string { return f.root }

// String identifying the remote
func (f *Fs) String() string { return fmt.Sprintf("idrive{%s}", f.root) }

// Features of the remote
func (f *Fs) Features() *fs.Features { return f.features }

// Precision of the filesystem
func (f *Fs) Precision() time.Duration {
	return 1 * time.Second // fs.ModTimeNotSupported
}

// Hashes supported by the filesystem
func (f *Fs) Hashes() hash.Set {
	var none hash.Set
	return none
}

// pathSplit splits path into dir and file
func pathSplit(p string) (dir, file string) {
	dir, file = path.Split(strings.Trim(p, "/"))
	dir = strings.TrimSuffix(dir, "/")
	return
}

// toNodePath returns server path for given remote
func (f *Fs) toNodePath(remote string) string {
	return f.opt.Enc.FromStandardPath(path.Join(f.root, remote))
}

// getNode returns a file/directory by traversing its path
func (f *Fs) getNode(nodePath string) (node *icloud.DriveNode, err error) {
	node = f.rootNode
	if nodePath == "" {
		return
	}
	for _, name := range strings.Split(nodePath, "/") {
		if node, err = node.Get(name); err != nil {
			node = nil
			break
		}
	}
	return
}

// Mkdir makes a directory.
// No error is returned if the directory already exists.
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.mkdir(f.toNodePath(dir))
	return err
}

func (f *Fs) mkdir(nodePath string) (*icloud.DriveNode, error) {
	node := f.rootNode
	if nodePath == "" {
		return node, nil
	}
	for _, name := range strings.Split(nodePath, "/") {
		child, err := node.Get(name)
		if err == icloud.ErrNotFound {
			err = node.Mkdir(name)
			node.Stale()
			if err == nil {
				child, err = node.Get(name)
			}
		}
		if err != nil {
			return nil, err
		}
		node = child
	}
	return node, nil
}

// Rmdir removes the directory if empty
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.rmdir(f.toNodePath(dir), true)
}

// Purge removes the directory with contents
// Return an error if it doesn't exist
func (f *Fs) Purge(ctx context.Context, dir string) error {
	return f.rmdir(f.toNodePath(dir), false)
}

func (f *Fs) rmdir(nodePath string, checkEmpty bool) error {
	if nodePath == "" {
		return fs.ErrorNotDeleting // refuse to remove Drive root
	}

	parentDir, name := pathSplit(nodePath)
	parent, err := f.getNode(parentDir)
	switch err {
	case nil: // ok
	case icloud.ErrNotFound:
		return fs.ErrorDirNotFound
	default:
		return err
	}

	child, err := parent.Get(name)
	switch err {
	case nil: // ok
	case icloud.ErrNotDir, icloud.ErrNotFound:
		return fs.ErrorDirNotFound
	default:
		return err
	}

	if checkEmpty && child.IsDir() {
		list, err := child.Children()
		if err != nil {
			return fmt.Errorf("cannot check directory content: %w", err)
		}
		if len(list) > 0 {
			return fs.ErrorDirectoryNotEmpty
		}
	}

	_ = child.Delete()
	parent.Stale() // force parent refresh

	// recheck and retry for eventual consistency
	if child, err = parent.Get(name); err != nil {
		return nil
	}
	err = child.Delete()
	parent.Stale()
	return err
}

// List the objects and directories in dir into entries.
// The entries can be returned in any order.
// Returns fs.ErrorDirNotFound if the directory isn't found.
// The dir should be "" to list the root.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	node, err := f.getNode(f.toNodePath(dir))
	if err == icloud.ErrNotFound {
		err = fs.ErrorDirNotFound
	}
	if err != nil {
		return nil, err
	}
	children, err := node.Children()
	if err == icloud.ErrNotDir {
		err = fs.ErrorIsFile
	}
	if err != nil {
		return nil, err
	}
	var noTime time.Time
	var list fs.DirEntries
	for _, node := range children {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(node.Name()))
		if node.IsDir() {
			list = append(list, fs.NewDir(remote, noTime))
		} else {
			list = append(list, f.newObject(remote, node))
		}
	}
	return list, nil
}

// Move src to this remote using server side move operations.
// This is stored with the remote path given
// It returns the destination Object and a possible error
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	o, ok := src.(*Object)
	if !ok || o.f.opt.Username != f.opt.Username {
		fs.Debugf(o.f, "Can't move file - not same remote type")
		return nil, fs.ErrorCantMove
	}
	srcDir, _ := pathSplit(o.f.toNodePath(o.remote))
	dstDir, dstName := pathSplit(f.toNodePath(remote))
	if srcDir == dstDir {
		err := o.rename(dstName)
		if parent2, err2 := f.getNode(dstDir); err2 == nil {
			parent2.Stale() // FIXME
		}
		if err != nil {
			return nil, err
		}
		return o, nil
	}
	fs.Debugf(f, "iCloud Drive could only rename a file")
	return nil, fs.ErrorCantMove
}

func (o *Object) rename(newName string) error {
	dirPath, oldName := pathSplit(o.f.toNodePath(o.remote))
	if oldName == newName {
		return nil
	}

	parent, err := o.f.getNode(dirPath)
	switch err {
	case nil: // ok
	case icloud.ErrNotFound:
		return fs.ErrorObjectNotFound
	default:
		return err
	}
	if !parent.IsDir() {
		return fs.ErrorObjectNotFound
	}

	dstNode, err := parent.Get(newName)
	switch err {
	case nil:
		if err := dstNode.Delete(); err != nil {
			return err
		}
	case icloud.ErrNotFound:
		// ok
	default:
		return err
	}
	err = o.n.Rename(newName)
	parent.Stale()
	return err
}

// DirMove moves src, srcRemote to this remote at dstRemote using server side move.
// If destination exists then return fs.ErrorDirExists.
// Note: iCloud Drive can only rename nodes.
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	fsrc, ok := src.(*Fs)

	reason := ""
	switch {
	case !ok:
		reason = "remote"
	case fsrc.opt.Username != f.opt.Username:
		reason = "owner"
	case fsrc.opt.Enc != f.opt.Enc:
		reason = "encoding"
	}
	if reason != "" {
		fs.Debugf(f, "Can't move directory - incompatible %s", reason)
		return fs.ErrorCantDirMove
	}

	srcDir, srcName := pathSplit(fsrc.toNodePath(srcRemote))
	dstDir, dstName := pathSplit(f.toNodePath(dstRemote))
	if srcDir == dstDir {
		err := f.renameDir(srcDir, srcName, dstName)
		if parent2, err2 := fsrc.getNode(srcDir); err2 == nil {
			parent2.Stale() // FIXME
		}
		return err
	}

	fs.Debugf(fsrc, "Leverage operations to move iCloud Drive directory")
	fCopy := *f
	featuresCopy := *f.features
	featuresCopy.DirMove = nil // force fallback in operations.DirMove
	fCopy.features = &featuresCopy
	fCopy.root = ""
	// FIXME Encode root
	srcAdjust := path.Join(fsrc.root, srcRemote)
	dstAdjust := path.Join(f.root, dstRemote)
	return operations.DirMove(ctx, &fCopy, srcAdjust, dstAdjust)
}

func (f *Fs) renameDir(dirPath, srcName, dstName string) error {
	parent, err := f.getNode(dirPath)
	switch err {
	case nil: // ok
	case icloud.ErrNotFound:
		return fs.ErrorDirNotFound
	default:
		return err
	}

	if !parent.IsDir() {
		return fs.ErrorDirNotFound
	}
	srcNode, err := parent.Get(srcName)
	switch err {
	case nil: // ok
	case icloud.ErrNotFound:
		return fs.ErrorDirNotFound
	default:
		return err
	}

	if srcName == dstName {
		return fs.ErrorDirExists // As per integration test
	}

	_, err = parent.Get(dstName)
	switch err {
	case nil:
		return fs.ErrorDirExists
	case icloud.ErrNotFound:
		// ok
	default:
		return err
	}

	err = srcNode.Rename(dstName)
	parent.Stale()
	return err
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	nodePath := f.toNodePath(remote)
	if nodePath == "" {
		return nil, fs.ErrorIsDir
	}
	node, err := f.getNode(nodePath)
	if err == icloud.ErrNotFound {
		return nil, fs.ErrorObjectNotFound
	}
	if err != nil {
		return nil, err
	}
	if node.IsDir() {
		return nil, fs.ErrorIsDir
	}
	return f.newObject(remote, node), nil
}

// Return an Object from a path
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObject(remote string, node *icloud.DriveNode) fs.Object {
	return &Object{remote: remote, f: f, n: node}
}

// Object describes an iCloud Drive file node
type Object struct {
	remote string
	f      *Fs
	n      *icloud.DriveNode
}

// ModTime returns the modification date of the file
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.n.Modified()
}

// Storable is always true
func (o *Object) Storable() bool {
	return true
}

// SetModTime is impossible
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

// Open the file for read.  Call Close() on the returned io.ReadCloser
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	size := o.Size()
	offset := int64(0)
	limit := int64(-1)
	for _, option := range options {
		switch opt := option.(type) {
		case *fs.SeekOption:
			offset = opt.Offset
		case *fs.RangeOption:
			offset, limit = opt.Decode(size)
		default:
			if option.Mandatory() {
				fs.Errorf(o.f, "Unsupported mandatory option: %v", option)
			}
		}
	}
	if limit < 0 {
		limit = size - offset
	}
	end := offset + limit
	if end > size {
		end = size
		limit = end - offset
	}

	stream, err := o.n.Open()
	if err != nil {
		return nil, err
	}
	if offset == 0 && end == size {
		return stream, nil // full stream requested
	}
	if offset > 0 {
		if _, err = io.CopyN(ioutil.Discard, stream, offset); err != nil {
			_ = stream.Close()
			return nil, err
		}
	}
	stream = readers.NewLimitedReadCloser(stream, limit)
	return stream, nil
}

// Put in to the remote path
// May create the object even if it returns an error.
// If so will return the object and the error, otherwise will return.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	o := f.newObject(src.Remote(), nil) // temporary object without a node
	if err := o.Update(ctx, in, src, options...); err != nil {
		return nil, err
	}
	return o, nil
}

// PutStream uploads to the remote path with the modTime given of indeterminate size
// May create the object even if it returns an error.
// If so will return the object and the error, otherwise will return nil and the error.
/*
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, fs.ErrorNotImplemented
}
*/

// Update the object
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	dir, name := pathSplit(o.f.toNodePath(o.remote))
	parent, err := o.f.getNode(dir)
	if err == icloud.ErrNotFound {
		parent, err = o.f.mkdir(dir) // Create parent directory if did not exist
	}
	if err != nil {
		return err
	}
	if !parent.IsDir() {
		return fs.ErrorDirNotFound
	}
	if oldNode, err := parent.Get(name); err == nil {
		err = oldNode.Delete()
		parent.Stale() // force directory refresh after delete
		if err != nil {
			return fmt.Errorf("cannot delete old file version: %w", err)
		}
	}
	err = parent.PutStream(in, name, src.Size(), src.ModTime(ctx))
	parent.Stale() // force directory refresh after upload
	if err != nil {
		return err
	}
	node, err := parent.Get(name)
	if err == nil {
		o.n = node
	}
	return err
}

// Remove object
func (o *Object) Remove(ctx context.Context) error {
	return o.n.Delete()
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info { return o.f }

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the SHA-1 of an object returning a lowercase hex string
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.n.Size()
}

// Check the interfaces are satisfied
var (
	_ fs.Fs       = (*Fs)(nil)
	_ fs.Mover    = (*Fs)(nil)
	_ fs.DirMover = (*Fs)(nil)
	_ fs.Purger   = (*Fs)(nil)
	_ fs.Object   = (*Object)(nil)
)
