// Package baidupcs provides an interface to the Baidu PCS
// object storage system.
// (aka Baidu Yun, Baidu Pan, Baidu NetDisk)
package baidupcs

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/readers"

	"github.com/qjfoidnh/Baidu-Login"
	"github.com/qjfoidnh/BaiduPCS-Go/baidupcs"
	"github.com/qjfoidnh/BaiduPCS-Go/baidupcs/pcserror"
	"github.com/qjfoidnh/BaiduPCS-Go/requester"
	"github.com/qjfoidnh/BaiduPCS-Go/requester/multipartreader"
)

const (
	defaultAppID             = "260149"
	defaultUserAgent         = "netdisk;1.0"
	defaultRapidUploadCutoff = fs.SizeSuffix(16 * 1024)
	defaultChunkSize         = fs.SizeSuffix(32 * 1024 * 1024)
	minSleep                 = 10 * time.Millisecond
	maxSleep                 = 2 * time.Second
	decayConstant            = 2 // bigger for slower decay, exponential
	hexLetters               = "0123456789abcdef"
	configBDUSS              = "bduss"
	configAppID              = "appid"
	configUserAgent          = "user_agent"
	configUseHTTPS           = "use_https"
	configRapidUploadCutoff  = "rapid_upload_cutoff"
	configChunkSize          = "chunk_size"
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "baidupcs",
		Description: "Baidu PCS (aka Baidu Yun, Baidu Pan, Baidu NetDisk)",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{
			{
				Name:     configBDUSS,
				Help:     "BDUSS obtained in user's cookie",
				Default:  "",
				Advanced: true,
			},
			{
				Name:     configAppID,
				Help:     "AppID used to connect to Baidu",
				Default:  defaultAppID,
				Advanced: true,
			},
			{
				Name:     configUserAgent,
				Help:     "User Agent to use when sending requests",
				Default:  defaultUserAgent,
				Advanced: true,
			},
			{
				Name:     configUseHTTPS,
				Help:     "Whether to use HTTPS connection.",
				Default:  true,
				Advanced: true,
			},
			{
				Name:     configRapidUploadCutoff,
				Help:     "Try rapid upload only if a file is >= this size. Use 0 to disable rapid upload.",
				Default:  defaultRapidUploadCutoff,
				Advanced: true,
			},
			{
				Name:     configChunkSize,
				Help:     "Chunk size when uploading",
				Default:  defaultChunkSize,
				Advanced: true,
			},
			{
				Name:     config.ConfigEncoding,
				Help:     config.ConfigEncodingHelp,
				Advanced: true,
				// Baidu rejects many special characters
				// By default use safe encoding to have tests pass:
				// encoding = Slash,Ctl,RightPeriod,RightSpace,InvalidUtf8,Asterisk,BackSlash,Colon,DoubleQuote,LtGt,Pipe,Question
				Default: (encoder.EncodeSlash |
					encoder.EncodeCtl |
					encoder.EncodeRightPeriod |
					encoder.EncodeRightSpace |
					encoder.EncodeBackSlash |
					encoder.EncodeWin |
					encoder.EncodeInvalidUtf8),
				Examples: []fs.OptionExample{{
					// Let users disable encoding completely
					Value: "none",
					Help:  "Do not encode file names",
				}},
			},
		},
	})
}

// Options defines the configuration for this backend
type Options struct {
	BDUSS             string               `config:"bduss"`
	AppID             string               `config:"appid"`
	UserAgent         string               `config:"user_agent"`
	UseHTTPS          bool                 `config:"use_https"`
	RapidUploadCutoff fs.SizeSuffix        `config:"rapid_upload_cutoff"`
	ChunkSize         fs.SizeSuffix        `config:"chunk_size"`
	Enc               encoder.MultiEncoder `config:"encoding"`
}

// Config ...
func Config(ctx context.Context, name string, m configmap.Mapper, cfg fs.ConfigIn) (*fs.ConfigOut, error) {
	// Skip login if BDUSS is specified by user
	if bduss, _ := m.Get(configBDUSS); bduss != "" {
		return nil, nil
	}

	fmt.Printf("Baidu username / email / phone number: ")
	username := config.ReadLine()
	fmt.Printf("Password: ")
	password := config.ReadPassword()

	loginClient := baidulogin.NewBaiduClinet()

	var bduss, code, codeStr string
	success := false
	for !success {
		loginJSON := loginClient.BaiduLogin(username, password, code, codeStr)
		switch loginJSON.ErrInfo.No {
		case "0": // Success
			bduss = loginJSON.Data.BDUSS
			success = true
		case "400023", "400101": // 2FA
			fmt.Println("Please choose a method to complete 2FA:")

			var methods []string
			phone := loginJSON.Data.Phone
			if phone != "未找到手机号" {
				methods = append(methods, "pPhone")
			}
			email := loginJSON.Data.Email
			if email != "未找到邮箱地址" {
				methods = append(methods, "eEmail")
			}

			method := map[string]string{
				"p": "mobile",
				"e": "email",
			}[string(config.Command(methods))]
			codeMsg := loginClient.SendCodeToUser2(method, loginJSON.Data.Token)
			fmt.Printf("Code requested. (Message from remote: %s)\n", codeMsg)

			fmt.Printf("Please enter the code you received: ")
			code = config.ReadLine()
			loginJSON = loginClient.VerifyCode2(method, loginJSON.Data.Token, code, loginJSON.Data.U)
			if loginJSON.ErrInfo.No != "0" {
				log.Fatalf("unable to complete 2FA: %s", loginJSON.ErrInfo.Msg)
			}

			bduss = loginJSON.Data.BDUSS
			success = true
		case "500001", "500002": // Captcha
			fmt.Println("Captcha required. Please open the link to see the image.")
			fmt.Printf("(Message from remote: %s)\n", loginJSON.ErrInfo.Msg)
			codeStr = loginJSON.Data.CodeString
			if codeStr == "" {
				log.Fatalf("received empty codeString from remote")
			}

			fmt.Println("https://wappass.baidu.com/cgi-bin/genimage?" + codeStr)
			fmt.Println("Please enter the code you see: ")
			code = config.ReadLine()
			continue // 2FA might be required even after captcha
		default: // Error
			log.Fatalf("unable to login; err code: %s, err message: %s", loginJSON.ErrInfo.No, loginJSON.ErrInfo.Msg)
		}
	}
	m.Set(configBDUSS, bduss)
	return nil, nil
}

func shouldRetry(resp *http.Response, err error) (bool, error) {
	if err != nil {
		if pcsErr, ok := err.(pcserror.Error); ok {
			return pcsErr.GetErrType() == pcserror.ErrTypeNetError, err
		}
		return false, err
	}
	return false, err
}

// Fs represents a remote box
type Fs struct {
	name     string             // name of this remote
	root     string             // the path we are working on
	opt      *Options           // parsed options
	features *fs.Features       // optional features
	srv      *baidupcs.BaiduPCS // the connection to the server
	pacer    *fs.Pacer
	// unused uploadToken *pacer.TokenDispenser // control concurrency
}

func (f *Fs) newHTTPClient() *requester.HTTPClient {
	client := requester.NewHTTPClient()
	client.SetHTTPSecure(f.opt.UseHTTPS)
	client.SetUserAgent(f.opt.UserAgent)
	return client
}

func (f *Fs) newFragmentUploadFunc(size int64, chunk *readers.RepeatableReader) baidupcs.UploadFunc {
	return func(uploadURL string, jar http.CookieJar) (resp *http.Response, err error) {
		client := f.newHTTPClient()
		client.SetCookiejar(jar)
		client.SetTimeout(0)

		mr := multipartreader.NewMultipartReader()
		mr.AddFormFile("uploadedfile", "", &readerLen64{
			reader: interface{}(chunk).(io.Reader),
			len:    size,
		})
		err = mr.CloseMultipart()
		if err != nil {
			return nil, err
		}

		err = f.pacer.Call(func() (bool, error) {
			resp, err = client.Req("POST", uploadURL, mr, nil)
			if err != nil {
				_, seekErr := chunk.Seek(0, io.SeekStart)
				if seekErr != nil {
					return false, errors.Wrapf(seekErr, "unable to seek during retry")
				}
				return true, err
			}
			return false, err
		})

		return resp, err
	}
}

func (f *Fs) newDownloadFunc(rPointer *io.ReadCloser, openOpts ...fs.OpenOption) baidupcs.DownloadFunc {
	return func(downloadURL string, jar http.CookieJar) error {
		client := f.newHTTPClient()
		client.SetCookiejar(jar)
		client.SetKeepAlive(true)
		client.SetTimeout(0)

		headers := make(map[string]string)
		for _, option := range openOpts {
			k, v := option.Header()
			if len(k) > 0 {
				headers[k] = v
			}
		}
		resp, err := client.Req("GET", downloadURL, nil, headers)
		if err != nil {
			return err
		}
		*rPointer = resp.Body
		return nil
	}
}

// About ...
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	total, used, err := f.srv.QuotaInfo()
	if err != nil {
		return nil, err
	}

	free := total - used
	return &fs.Usage{
		Total: &total,
		Used:  &used,
		Free:  &free,
	}, nil
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("baidupcs root '%s'", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision ...
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash types of the filesystem
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.MD5)
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This returns fs.ErrorDirNotFound if the directory isn't found.
//
// This function accepts file paths and treat them the same as directories
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	var rawEntries baidupcs.FileDirectoryList
	err = f.pacer.Call(func() (bool, error) {
		rawEntries, err = f.srv.FilesDirectoriesList(f.getServerSidePath(dir), baidupcs.DefaultOrderOptions)
		return shouldRetry(nil, err)
	})
	if err != nil {
		if pcsErr, ok := err.(pcserror.Error); ok && pcsErr.GetErrType() == pcserror.ErrTypeRemoteError {
			return nil, fs.ErrorDirNotFound
		}
		return
	}
	for _, rawEntry := range rawEntries {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(rawEntry.Filename))
		if rawEntry.Isdir {
			d := fs.NewDir(remote, time.Unix(rawEntry.Mtime, 0))
			entries = append(entries, d)
		} else {
			o, err := f.newObjectWithInfo(remote, rawEntry)
			if err != nil {
				return nil, err
			}
			entries = append(entries, o)
		}
	}
	return
}

// Copy src to this remote using server side copy operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't copy - not same remote type")
		return nil, fs.ErrorCantCopy
	}
	err := srcObj.readMetaData()
	if err != nil {
		return nil, err
	}

	err = f.pacer.Call(func() (bool, error) {
		return shouldRetry(nil, f.srv.Copy(&baidupcs.CpMvJSON{
			From: srcObj.fs.getServerSidePath(srcObj.remote),
			To:   f.getServerSidePath(remote),
		}))
	})
	if err != nil {
		return f.newObjectLocal(remote, srcObj.modTime, srcObj.size), nil
	}
	return nil, err
}

// Move src to this remote using server side move operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same remote type")
		return nil, fs.ErrorCantMove
	}

	err := f.pacer.Call(func() (bool, error) {
		err := f.srv.Rename(srcObj.fs.getServerSidePath(src.Remote()), f.getServerSidePath(remote))
		return shouldRetry(nil, err)
	})
	if err != nil {
		return nil, err
	}
	srcObj.remote = remote
	return srcObj, nil
}

// DirMove moves src, srcRemote to this remote at dstRemote
// using server side move operations.
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	srcFs, ok := src.(*Fs)
	if !ok {
		fs.Debugf(srcFs, "Can't move directory - not same remote type")
		return fs.ErrorCantDirMove
	}
	srcPath := srcFs.getServerSidePath(srcRemote)
	dstPath := f.getServerSidePath(dstRemote)

	// Refuse to move to or from the root
	if srcPath == "" || dstPath == "" {
		fs.Debugf(src, "DirMove error: Can't move root")
		return errors.New("can't move root directory")
	}

	_, err := f.newObjectWithInfo(dstPath, nil)
	if err != nil {
		if err != fs.ErrorObjectNotFound {
			return err
		}
		_, err = f.Move(ctx, srcFs.newObjectLocal(srcRemote, time.Time{}, 0), dstRemote)
		return err
	}
	return fs.ErrorDirExists
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(remote, nil)
}

// Put in to the remote path
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	o := f.newObjectLocal(src.Remote(), src.ModTime(ctx), src.Size())
	return o, o.Update(ctx, in, src, options...)
}

// PutStream uploads to the remote path with the modTime given of indeterminate size
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.Put(ctx, in, src, options...)
}

// Mkdir makes the directory (container, bucket)
//
// Shouldn't return an error if it already exists
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return f.pacer.Call(func() (bool, error) {
		err := f.srv.Mkdir(f.getServerSidePath(dir))
		if err != nil && err.GetRemoteErrCode() == 31061 { // Dir already exists
			return false, nil
		}
		return shouldRetry(nil, err)
	})
}

// Rmdir removes the directory (container, bucket) if empty
//
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	entries, err := f.List(ctx, dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fs.ErrorDirectoryNotEmpty
	}
	return f.pacer.Call(func() (bool, error) {
		return shouldRetry(nil, f.srv.Remove(f.getServerSidePath(dir)))
	})
}

// Return an Object from a path
//
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObjectWithInfo(remote string, info *baidupcs.FileDirectory) (fs.Object, error) {
	o := f.newObjectLocal(remote, time.Time{}, 0)
	var err error
	if info != nil {
		// Set info
		err = o.setMetaData(info)
	} else {
		err = o.readMetaData() // reads info and meta, returning an error
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (f *Fs) newObjectLocal(remote string, modTime time.Time, size int64) *Object {
	return &Object{
		fs:      f,
		remote:  remote,
		modTime: modTime,
		size:    size,
	}
}

func (f *Fs) getServerSidePath(p string) string {
	return f.opt.Enc.FromStandardPath(path.Clean(path.Join("/", f.root, "/", p)))
}

// Object describes a BaiduPCS object
//
// Will definitely have info but maybe not meta
type Object struct {
	fs          *Fs       // what this object is part of
	remote      string    // The remote path
	hasMetaData bool      // whether info below has been set
	size        int64     // size of the object
	modTime     time.Time // modification time of the object
	md5         string    // MD5 of the object content
}

// ModTime returns the modification date of the file
func (o *Object) ModTime(ctx context.Context) time.Time {
	err := o.readMetaData()
	if err != nil {
		fs.Logf(o, "Failed to read metadata: %v", err)
		return time.Now()
	}
	return o.modTime
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
	// TODO: multithread?
	var r io.ReadCloser
	err := o.fs.srv.DownloadFile(o.fs.getServerSidePath(o.remote), o.fs.newDownloadFunc(&r, options...))
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Update the object
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (err error) {

	// Rapid upload
	cutoff := o.fs.opt.RapidUploadCutoff
	var md5Sum string
	if cutoff > 0 && o.size >= int64(cutoff) {
		fs.Debugf(o, "testing rapid upload availability")
		md5Sum, err = src.Hash(ctx, hash.MD5)
		if err != nil {
			if err == hash.ErrUnsupported {
				fs.Debugf(o, "src does not support MD5 hash - skipping rapid upload")
			} else {
				return err
			}
		} else {
			o.md5 = md5Sum // TODO: Okay here?

			// According to BaiduPCS-Go, CRC32 is actually not required
			// and slice MD5 only needs to match the MD5 hex string format
			err = o.fs.srv.RapidUpload(o.fs.getServerSidePath(o.remote), md5Sum, generateRandomMD5(), "0", o.size)
			if err != nil {
				fs.Debugf(o, "starting regular upload because rapid upload failed: %v", err)
			} else {
				fs.Debugf(o, "rapid upload successful")
				return nil
			}
		}
	}

	// Regular upload
	// TODO: Refine this
	// TODO: Use MultiUploader?
	var checksumList []string
	remaining := o.size
	position := int64(0)
	for remaining > 0 {
		n := int64(o.fs.opt.ChunkSize)
		if remaining < n {
			n = remaining
		}
		chunk := readers.NewRepeatableReader(io.LimitReader(in, n))
		fs.Debugf(o, "Uploading segment %d/%d size %d", position, o.size, n)
		checksum, err := o.fs.srv.UploadTmpFile(o.fs.newFragmentUploadFunc(n, chunk))
		if err != nil {
			return err
		}
		remaining -= n
		position += n
		checksumList = append(checksumList, checksum)
	}

	// Commit
	policy := "overwrite"
	checkDir := false // FIXME true?
	err = o.fs.srv.UploadCreateSuperFile(policy, checkDir, o.fs.getServerSidePath(o.remote), checksumList...)
	if err != nil {
		return err
	}

	// Fix MD5 for uploaded file - from BaiduPCS-Go
	if md5Sum != "" {
		err = o.fs.srv.RapidUpload(o.fs.getServerSidePath(o.remote), md5Sum, generateRandomMD5(), "0", o.size)
		if err != nil {
			return errors.Wrap(err, "unable to fix MD5 for uploaded file (the file should have been uploaded)")
		}
		fs.Debugf(o, "fixed MD5 for this file on the server")
	} else {
		fs.Debugf(o, "src MD5 unavailable - not fixing md5 on server")
	}

	return nil
}

// Remove object
func (o *Object) Remove(ctx context.Context) error {
	return o.fs.pacer.Call(func() (bool, error) {
		return shouldRetry(nil, o.fs.srv.Remove(o.fs.getServerSidePath(o.remote)))
	})
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

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
	if t != hash.MD5 {
		return "", hash.ErrUnsupported
	}
	return o.md5, nil
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	err := o.readMetaData()
	if err != nil {
		fs.Logf(o, "Failed to read metadata: %v", err)
		return 0
	}
	return o.size
}

// readMetaData gets the metadata if it hasn't already been fetched
//
// it also sets the info
//
// Returns fs.ErrorObjectNotFound if not found
func (o *Object) readMetaData() (err error) {
	if o.hasMetaData {
		return nil
	}
	var info *baidupcs.FileDirectory
	err = o.fs.pacer.Call(func() (bool, error) {
		info0, err := o.fs.srv.FilesDirectoriesMeta(o.fs.getServerSidePath(o.remote))
		info = info0
		return shouldRetry(nil, err)
	})
	if err != nil {
		if pcsErr, ok := err.(pcserror.Error); ok && pcsErr.GetErrType() == pcserror.ErrTypeRemoteError {
			return fs.ErrorObjectNotFound
		}
		return err
	}
	return o.setMetaData(info)
}

// setMetaData sets the metadata from info
func (o *Object) setMetaData(info *baidupcs.FileDirectory) (err error) {
	o.hasMetaData = true
	o.size = info.Size
	o.md5 = info.MD5
	o.modTime = time.Unix(info.Mtime, 0)
	return nil
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := &Options{}
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	appID, err := strconv.Atoi(opt.AppID)
	if err != nil {
		log.Fatalf("cannot convert appid to int: %v", err)
	}

	root = strings.Trim(root, "/")
	f := &Fs{
		name: name,
		root: root,
		opt:  opt,
	}

	baiduURL := &url.URL{
		Scheme: "http",
		Host:   "pan.baidu.com",
	}
	baiduCookie := &http.Cookie{
		Name:   "BDUSS",
		Value:  opt.BDUSS,
		Domain: baidupcs.DotBaiduCom,
	}
	cli := requester.NewHTTPClient()
	cli.ResetCookiejar()
	cli.Jar.SetCookies(baiduURL, []*http.Cookie{baiduCookie})
	cli.SetUserAgent(opt.UserAgent)
	f.srv = baidupcs.NewPCSWithClient(appID, cli)
	f.srv.SetHTTPS(opt.UseHTTPS)

	f.pacer = fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))
	f.features = (&fs.Features{
		CaseInsensitive:         true,
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	// Ensure root is a directory
	entries, err := f.List(ctx, "")
	if err != nil {
		if err == fs.ErrorDirNotFound {
			// Neither file nor directory
			return f, nil
		}
		return nil, err
	}

	var rootIsFile bool
	entries.ForObject(func(o fs.Object) {
		if o.Remote() == path.Clean(path.Base(root)) {
			rootIsFile = true
		}
	})
	if rootIsFile {
		newRoot, _ := dircache.SplitPath(root)
		f.root = newRoot
		_, newErr := f.List(ctx, "")
		if newErr != nil {
			return nil, newErr
		}
		return f, fs.ErrorIsFile
	}

	return f, nil
}

func generateRandomMD5() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = hexLetters[rand.Intn(len(hexLetters))]
	}
	return string(b)
}

// Check the interfaces are satisfied
var (
	_ fs.Fs       = (*Fs)(nil)
	_ fs.Copier   = (*Fs)(nil)
	_ fs.Mover    = (*Fs)(nil)
	_ fs.DirMover = (*Fs)(nil)
	//_ fs.PublicLinker    = (*Fs)(nil)
	_ fs.Abouter = (*Fs)(nil)
	_ fs.Object  = (*Object)(nil)
)
