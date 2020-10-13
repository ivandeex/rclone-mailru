package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
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
)

var gotStreamReset bool
var out *log.Logger = log.New(os.Stderr, "", log.Ltime|log.Lmicroseconds)

// ==== CLIENT ====

func client(proto, serverAddr string, drain bool, testTime time.Duration) {
	scheme := "http"
	var client *http.Client
	switch proto {
	case "http1":
		client = http.DefaultClient
	case "http2":
		tr := &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, address string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial("tcp", address)
			},
		}
		client = &http.Client{
			Transport: tr,
			Timeout:   60 * time.Second,
		}
	case "https2":
		scheme = "https"
		tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client = &http.Client{Transport: tr}
	}

	endTime := time.Now().Add(testTime)
	rand.Seed(0)
	buf := make([]byte, maxSize+1)

	for loop := 1; time.Now().Before(endTime); loop++ {
		if loop%10000 == 0 {
			out.Printf("loop %dk\n", loop/1000)
		}

		size := randInt(minSize, maxSize)
		url := fmt.Sprintf("%s://%s/%d/%d/", scheme, serverAddr, loop, size)
		res, err := client.Get(url)
		if err != nil {
			out.Printf("client: GET error (%v)\n", err)
			return
		}
		body := res.Body

		num, err := io.ReadFull(body, buf[:size]) // don't wait for EOF, here be dragons
		if num != size || err != nil {
			out.Printf("client: read %d of %d bytes (%v)\n", num, size, err)
			return
		}
		if drain {
			num, err = body.Read(buf[:1]) // wait for EOF
			if num != 0 || err != io.EOF {
				out.Printf("client: invalid drain, read %d bytes (%v)\n", num, err)
				return
			}
		}
		err = body.Close()
		if err != nil {
			out.Printf("client: body close error (%v)\n", err)
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
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	num, err := io.Copy(w, io.LimitReader(file, size))
	if num != size || err != nil {
		out.Printf("server ERROR: loop %d wrote only %d of %d bytes (%v)\n", loop, num, size, err)
		gotStreamReset = true
	}
	_ = file.Close()
}

func server(proto string, addrCh chan<- string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		out.Fatalf("listen failed (%v)\n", err)
	}
	serverAddr := ln.Addr().String()
	out.Printf("listen on %s\n", serverAddr)
	addrCh <- serverAddr

	switch proto {
	case "http1":
		srv1 := &http.Server{
			Handler: &handler{},
		}
		_ = srv1.Serve(ln)
	case "http2":
		srv2 := &http2.Server{}
		opt2 := &http2.ServeConnOpts{
			Handler: &handler{},
		}
		con, err := ln.Accept()
		if err != nil {
			out.Fatalf("accept failed (%v)\n", err)
		}
		srv2.ServeConn(con, opt2)
	case "https2":
		cert := []tls.Certificate{selfSignedCert()}
		srv := &http.Server{
			Handler:   &handler{},
			TLSConfig: &tls.Config{Certificates: cert},
		}
		if err := http2.ConfigureServer(srv, nil); err != nil {
			out.Fatalf("cannot configure http2 tls server (%v)\n", err)
		}
		_ = srv.ServeTLS(ln, "", "")
	}

	_ = ln.Close()
}

func selfSignedCert() tls.Certificate {
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		out.Fatalf("private key failed (%v)\n", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pub := &priv.PublicKey

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	tmpl.BasicConstraintsValid = true

	derBytes, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		out.Fatalf("certificate failed (%v)\n", err)
	}

	crtBuf := &bytes.Buffer{}
	keyBuf := &bytes.Buffer{}
	err1 := pem.Encode(crtBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err2 := pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	if err1 != nil || err2 != nil {
		out.Fatalf("cannot encode x509 (%v, %v)\n", err1, err2)
	}
	keyPair, err := tls.X509KeyPair(crtBuf.Bytes(), keyBuf.Bytes())
	if err != nil {
		out.Fatalf("cannot create x509 key pair (%v)\n", err)
	}
	return keyPair
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
	usage := "usage: go run http2test.go http1|http2|https2 drain|nodrain seconds\n"
	if len(os.Args) != 4 {
		out.Fatalf(usage)
	}

	proto := os.Args[1]
	switch proto {
	case "http1", "http2", "https2":
		// ok
	default:
		out.Fatalf(usage)
	}

	var drain bool
	switch os.Args[2] {
	case "drain":
		drain = true
	case "nodrain":
		drain = false
	default:
		out.Fatalf(usage)
	}

	sec, err := strconv.ParseInt(os.Args[3], 10, 64)
	if err != nil || sec <= 0 {
		out.Fatalf(usage)
	}
	testTime := time.Duration(sec) * time.Second

	makeBigFile()
	addrCh := make(chan string)
	go server(proto, addrCh)
	client(proto, <-addrCh, drain, testTime)

	if gotStreamReset {
		out.Fatalf("GOT STREAM RESET!\n")
	}
	out.Printf("OK\n")
}
