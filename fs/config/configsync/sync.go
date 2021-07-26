package configsync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/rc"
	"github.com/rclone/rclone/lib/atexit"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

const (
	rcDefaultPort = 5572
	queueSize     = 10
	exitTimeout   = 100 * time.Millisecond
)

type receiver struct {
	url    string
	user   string
	pass   string
	client *http.Client
}

type message struct {
	section string
	key     string
	value   string
}

var (
	receivers []*receiver
	queue     chan message
	onExit    sync.Once
)

func newReceiver(ctx context.Context, urlStr string) (*receiver, error) {
	// Normalize URL
	if strings.HasPrefix(urlStr, ":") {
		urlStr = "localhost" + urlStr
	}
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(u.Host, ":") {
		u.Host = fmt.Sprintf("%s:%d", u.Host, rcDefaultPort)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	switch u.Scheme {
	case "rc":
		u.Scheme = "http"
	case "rcs":
		u.Scheme = "https"
	case "http", "https":
		// ok
	default:
		u.User = nil // Hide secrets from error message
		return nil, errors.Errorf("unknown scheme %q in url %q", u.Scheme, u.String())
	}

	// Extract user and password from URL
	r := &receiver{}
	if u.User != nil {
		r.user = u.User.Username()
		if password, ok := u.User.Password(); ok {
			r.pass = password
		}
	}
	if r.user == "" {
		if flag := pflag.Lookup("rc-user"); flag != nil && flag.Changed {
			r.user = flag.Value.String()
		}
	}
	if r.pass == "" {
		if flag := pflag.Lookup("rc-pass"); flag != nil && flag.Changed {
			r.pass = flag.Value.String()
		}
	}

	// Hide secrets from printable URL
	u.User = nil
	r.url = u.String()
	r.client = fshttp.NewClient(ctx)
	fs.Debugf(nil, "Added new config receiver %s", r.url)
	return r, nil
}

// Send config update to remote rclone instance
func (r *receiver) send(ctx context.Context, section, key, value string) error {
	// Prepare sync request
	param := rc.Params{fs.ConfigKeySyncPrefix + key: value}
	paramStr, err := json.Marshal(param)
	if err != nil {
		return errors.Wrap(err, "failed to encode json for sync parameters")
	}

	in := rc.Params{"name": section, "parameters": string(paramStr)}
	inStr, err := json.Marshal(in)
	if err != nil {
		return errors.Wrap(err, "failed to encode json for sync request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.url+"config/update", bytes.NewBuffer(inStr))
	if err != nil {
		return errors.Wrap(err, "failed to make sync request")
	}
	req.Header.Set("Content-Type", "application/json")
	if r.user != "" || r.pass != "" {
		req.SetBasicAuth(r.user, r.pass)
	}

	// Send sync request
	res, err := r.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "sync connection to %s failed", r.url)
	}
	defer fs.CheckClose(res.Body, &err)

	if res.StatusCode != http.StatusOK {
		bodyBuf, err := ioutil.ReadAll(res.Body)
		var bodyStr string
		if err == nil {
			bodyStr = strings.TrimSpace(string(bodyBuf))
		} else {
			bodyStr = err.Error()
		}
		return errors.Errorf("failed to get sync response (%s): %s", res.Status, bodyStr)
	}

	// Parse output
	out := rc.Params{}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return errors.Wrapf(err, "failed to decode response JSON from %s", r.url)
	}
	if error, _ := out.GetString("Error"); error != "" {
		return errors.Errorf("config sync to %s failed: %s", r.url, error)
	}

	return nil
}

// Setup the config senders
func Setup(urls []string) (configmap.SetterMaker, error) {
	var rs []*receiver
	for _, urlOrMore := range urls {
		urlOrMore = strings.TrimSpace(urlOrMore)
		if urlOrMore == "" {
			continue
		}
		for _, url := range strings.Split(urlOrMore, ",") {
			r, err := newReceiver(context.Background(), url)
			if err != nil {
				return nil, err
			}
			rs = append(rs, r)
		}
	}

	if len(rs) == 0 {
		return nil, nil
	}

	receivers = rs
	queue = make(chan message, queueSize)
	_ = atexit.Register(func() {
		onExit.Do(syncExit)
	})
	go syncTask()

	return syncSetterMaker(true), nil
}

// syncTask is a background goroutine sending updates out
func syncTask() {
	for queue != nil {
		m, ok := <-queue
		if !ok || m.key == "" {
			break
		}
		if strings.HasPrefix(m.key, fs.ConfigKeySyncPrefix) {
			fs.Debugf(nil, "Skip sending %s/%s to config receivers", m.section, m.key)
			return
		}
		time.Sleep(time.Millisecond)
		for _, r := range receivers {
			fs.Debugf(nil, "Sending %s/%s to config receiver %s", m.section, m.key, r.url)
			if err := r.send(context.Background(), m.section, m.key, m.value); err != nil {
				fs.Errorf(nil, "Failed sending %s/%s to %s: %v", m.section, m.key, r.url, err)
			}
		}
	}
}

func syncExit() {
	if len(queue) > 0 {
		fs.Debugf(nil, "waiting for config sync to finish...")
		endWait := time.Now().Add(exitTimeout)
		for len(queue) > 0 && time.Now().Before(endWait) {
			time.Sleep(time.Millisecond)
		}
		fs.Debugf(nil, "config sync finished")
	}
	if queue != nil {
		close(queue)
		queue = nil
	}
}

// Interface with configmap
type (
	syncSetterMaker bool
	syncSetter      string
)

func (syncSetterMaker) MakeSetter(section string) configmap.Setter {
	return syncSetter(section)
}

func (s syncSetter) Set(key, value string) {
	section := string(s)
	fs.Debugf(nil, "Config %s/%s updated, ready to sync", section, key)
	queue <- message{section: section, key: key, value: value}
}
