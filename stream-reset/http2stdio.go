package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const (
	randFile = "/dev/urandom"
	bigFile  = "/tmp/bigfile"
	minSize  = 500
	maxSize  = 65000
	maxTime  = 5 * time.Second
)

var gotStreamReset bool
var out *log.Logger = log.New(os.Stderr, "", log.Ltime|log.Lmicroseconds)

// ==== CLIENT ====

func client(rd io.ReadCloser, wr io.WriteCloser) {
	conn := &stdioConn{rd, wr}

	dialCount := 0
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, address string, cfg *tls.Config) (net.Conn, error) {
			if dialCount > 0 {
				out.Fatalf("must connect only once\n")
			}
			dialCount++
			return conn, nil
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}

	endTime := time.Now().Add(maxTime)
	rand.Seed(0)
	bufSpace := make([]byte, maxSize+1)
	loop := 1

	for time.Now().Before(endTime) {
		loop++
		if loop%10000 == 0 {
			out.Printf("client: loop %dk\n", loop/1000)
		}
		size := randInt(minSize, maxSize)
		url := fmt.Sprintf("http://localhost/%d/%d/", loop, size)
		res, err := client.Get(url)
		if err != nil {
			out.Printf("client: get error (%v)\n", err)
			return
		}
		body := res.Body
		buf := bufSpace[:size]
		num, err := io.ReadFull(body, buf)
		if num != size || err != nil {
			out.Printf("client: read %d of %d bytes (%v)\n", num, size, err)
			return
		}
		err = body.Close()
		if err != nil {
			out.Printf("client: close error (%v)\n", err)
			return
		}
	}
}

func randInt(min, max int) int {
	return min + rand.Intn(max-min+1)
}

// ==== SERVER ====

type handler struct{}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 {
		out.Fatalf("server: invalid url %q\n", path)
		return
	}
	loop, err1 := strconv.ParseInt(parts[0], 10, 64)
	size, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil {
		out.Fatalf("server: invalid url %q\n", path)
		return
	}
	file, err := os.Open(bigFile)
	if err != nil {
		out.Fatalf("server: %s not found\n", bigFile)
		return
	}
	defer close(file)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	num, err := io.Copy(w, io.LimitReader(file, size))
	if err != nil {
		out.Printf("server ERROR: loop %d wrote only %d of %d bytes (%v)\n", loop, num, size, err)
		gotStreamReset = true
		return
	}
}

func close(file *os.File) {
	_ = file.Close()
}

func server() {
	hdl := &handler{}
	srv := &http2.Server{}
	opts := &http2.ServeConnOpts{
		Handler: hdl,
	}
	conn := &stdioConn{os.Stdin, os.Stdout}
	srv.ServeConn(conn, opts)
}

// ==== STDIO ====

type stdioConn struct {
	rd io.ReadCloser
	wr io.WriteCloser
}

func (sc *stdioConn) Read(p []byte) (int, error) {
	return sc.rd.Read(p)
}

func (sc *stdioConn) Write(p []byte) (int, error) {
	return sc.wr.Write(p)
}

func (sc *stdioConn) Close() error {
	rerr := sc.rd.Close()
	werr := sc.wr.Close()
	if rerr != nil {
		return rerr
	}
	return werr
}

func (sc *stdioConn) SetDeadline(t time.Time) error {
	return nil
}

func (sc *stdioConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (sc *stdioConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type addr struct{}

func (a addr) Network() string {
	return "stdio"
}

func (a addr) String() string {
	return "stdio"
}

func (sc *stdioConn) LocalAddr() net.Addr {
	return addr{}
}

func (sc *stdioConn) RemoteAddr() net.Addr {
	return addr{}
}

// ==== FORK ====

type serverProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (sp *serverProcess) start() error {
	var err error
	progPath, _ := os.Executable()
	sp.cmd = exec.Command(progPath, "server")
	sp.stdin, err = sp.cmd.StdinPipe()
	if err != nil {
		return err
	}
	sp.stdout, err = sp.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	sp.stderr, err = sp.cmd.StderrPipe()
	if err != nil {
		return err
	}
	err = sp.cmd.Start()
	if err != nil {
		return err
	}
	return nil
}

func (sp *serverProcess) stop() {
	err := sp.cmd.Process.Kill()
	if err != nil {
		return
	}
	_, err = sp.cmd.Process.Wait()
	if err != nil {
		return
	}
	outb, err := ioutil.ReadAll(sp.stderr)
	if err != nil {
		return
	}
	out.Printf("test server said:\n%s\n", bytes.TrimSpace(outb))
	return
}

// ==== MAIN ====

func makeBigFile() {
	ddArgs := []string{
		fmt.Sprintf("if=%s", randFile),
		fmt.Sprintf("of=%s", bigFile),
		fmt.Sprintf("count=%d", maxSize+100),
		"bs=1",
	}
	err := exec.Command("dd", ddArgs...).Run()
	if err != nil {
		out.Fatalf("test: dd failed (%v)\n", err)
	}
}

func main() {
	switch {
	case len(os.Args) == 1:
		makeBigFile()
		sp := &serverProcess{}
		err := sp.start()
		if err != nil {
			out.Fatalf("test: server start failed (%v)\n", err)
		}
		defer sp.stop()
		client(sp.stdout, sp.stdin)
	case len(os.Args) == 2 && os.Args[1] == "server":
		server()
	default:
		out.Fatalf("test: wrong usage\n")
	}
	if gotStreamReset {
		out.Fatalf("GOT STREAM RESET!\n")
	}
	out.Printf("bye\n")
}
