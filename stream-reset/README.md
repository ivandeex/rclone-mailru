# Premature Stream Reset Between Restic And Rclone

## The Problem

Go HTTP/2 client could send with some probability an unexpected `stream reset`
after reading full response body from an HTTP/2 server (Golang or other).
See issue "_RST_STREAM sent to a closed stream_":
https://github.com/golang/go/issues/41570

For example, restic and rclone internally talk HTTP/2 on a stdio pipe between
the processes. Sometimes restic sends back a stream reset to rclone after
reading partial object, making rclone print the error message
"[Didn't finish writing GET request](https://github.com/rclone/rclone/blob/v1.52-stable/cmd/serve/httplib/serve/serve.go#L88)"
(see https://github.com/rclone/rclone/issues/2598).
This happens `after` rclone has completed sending partial object to restic
and does not cause data corruption (see the section ["gory details"](#the-gory-details) below).

The [probability of hitting stream reset](#distribution-of-delays-till-http2-eof)
depends on the size of your backup repository.

See the section ["running the test"](#running-the-test) below on how to
reproduce the issue with restic and rclone.

Or run a standalone test [http2test.go](https://github.com/ivandeex/rclone/blob/stream-reset/stream-reset/http2test.go)
from this directory, which does not require restic or rclone:
```
go run http2test.go http1 nodrain 10
```
runs successfully
```
go run http2test.go http2 nodrain 10
```
prints error messages
```
go run http2test.go http2 drain 10
```
is successful again.

## The Solution

Implementations of HTTP/1.1 and HTTP/2 in Go seem to treat the end of
request-response roundtrip differently in part due to inherent difference between
the keep-alive connections in HTTP/1.1 and multiplexed TCP streams in HTTP/2.
An explicit wait for EOF after reading response, while not important in HTTP/1.1,
really helps to prevent above issues in case of HTTP/2.

Download fixed restic and give it a try: https://github.com/ivandeex/restic/releases/tag/v0.10-iva04

See proposed restic patch here: https://github.com/ivandeex/restic/commits/master

It drains rclone response body till EOF before calling `Close`,
but does it on a separate goroutine so that main restic process is not delayed.
A [dedicated section below](#distribution-of-delays-till-http2-eof)
measures involved delays. The drain approach was once discussed in
[restic issue 1561](https://github.com/restic/restic/issues/1561#issuecomment-373118890) but was not implemented.

## The Gory Details

This section is based on test logs
([rclone-err.log.snippet.txt](https://github.com/ivandeex/rclone/blob/stream-reset/stream-reset/snippets/rclone-err.log.snippet.txt)
and [restic-err.log.snippet.txt](https://github.com/ivandeex/rclone/blob/stream-reset/stream-reset/snippets/restic-err.log.snippet.txt))
and source code.

Restic requests partial objects from rclone by calling various wrappers around
[ReadAt](https://github.com/restic/restic/blob/v0.10.0/internal/restic/readerat.go#L27)
which takes input buffer `p` and calls rclone backend's `Load()` that defaults to
[backend.DefaultLoad](https://github.com/restic/restic/blob/v0.10.0/internal/backend/utils.go#L53).
The latter function first creates an HTTP range request to rclone via `stdio` pipe in
[rest.openReader](https://github.com/restic/restic/blob/v0.10.0/internal/backend/rest/rest.go#L193)
and hands response body over to
[io.ReadFull](https://github.com/golang/go/blob/release-branch.go1.14/src/io/io.go#L321)
which reads _exactly_ the number of bytes in an input buffer `p` but no more.
It does not wait for EOF.

Not waiting for EOF would be correct if we used `HTTP/1.1` between restic and rclone.
Implementation of HTTP/1.1 in `net.http` limited response body to the request's content length
(see [readTransfer](https://github.com/golang/go/blob/release-branch.go1.14/src/net/http/transfer.go#L557))
and blocked a caller attempting to read more
(see [persistConn.readLoop](https://github.com/golang/go/blob/release-branch.go1.14/src/net/http/transport.go#L2023)).

This enforcement is justified by the need to reuse `keep-alive` connections
for new requests after roundtrip. The HTTP/1.1 standard says that
"_The default HTTP client's Transport may not reuse HTTP/1.x `keep-alive`
TCP connections if the Body is not read to `completion` and closed._"
Moreover, golang's `net.http` documentation states that
"_If the Body is not both read to `EOF` and closed, the Client's underlying Transport
may not be able to re-use a persistent TCPconnection for a subsequent request_"
(see https://golang.org/pkg/net/http/#Response).

`HTTP/2` uses a different transport paradigm of multiplexed TCP connections.
Every roundtrip (a request followed by response) makes up a `stream`
consisting of a number of `frames` exchanged between client (restic)
and server (rclone) marked by a specific `stream identifier`.
Many streams share a single TCP connection, so that frames of a stream
are interleaved by frames of other streams. Data frames can be marked by
the `stream end` flag. Also there is a separate `reset stream` control frame.
A client application should implement a control loop calling `net.http` library
APIs, while a server application is a set of callbacks (`Handler`s).
Client request/response handling is internalally implemented by `struct Transport`,
while server control loop is implemented by `struct Server`.

Actual sending of frames on wire is performed by an internal `net.http2` goroutine
attached to the TCP connection and running in background. Incoming control and data
frames are ingested from TCP by another internal goroutine. Let's consider
a server sending response body to client, namely the `last` response buffer
(see rclone's [serve.Object](https://github.com/rclone/rclone/blob/v1.52-stable/cmd/serve/httplib/serve/serve.go#L86)).
The sending is performed from inside the server handler, but the end of stream
mark can be sent only after the handler has returned. Thus, the last buffer
will be sent without the `stream end` flag. The buffer internally ends up in
[serverConn.writeDataFromHandler](https://github.com/golang/net/blob/release-branch.go1.14/http2/server.go#L1013),
which sends it to the writing goroutine channel and blocks in `select` waiting
either for `write done` signal from the writing goroutine or for special events
from receiving goroutine such as flow control frames extending buffer quota
or marking termination of a particular stream or the whole TCP connection.
Let's call it the `critical interval`.

When the wait is done and the handler returns, the server sends a separate
`EOF frame`, a zero-length data frame with the `stream end` flag set.
In the meantime restic has received all `range` (or `Content-Length`) bytes
completely and called `response.Body.Close()` before the EOF frame had
a chance to reach the client's HTTP receiver goroutine, and consequently
[transportResponseBody.Close](https://github.com/golang/net/blob/release-branch.go1.14/http2/transport.go#L2087)
sends `stream reset` to the server. Normally the `write done` signal
should have already unblocked the server handler, but in case the
network media is **very** fast (this is true for stdio pipes) or
under high load when the channel between writing goroutine and server
handlers is busy, the stream reset could reach `select` **first**
(see [writeDataFromHandler](https://github.com/golang/net/blob/release-branch.go1.14/http2/server.go#L1030)).
Probability of this is low but not strictly zero, and depends on the
distribution of the critical interval.

## Running The Test

The attached
[Dockerfile](https://github.com/ivandeex/rclone/blob/stream-reset/stream-reset/Dockerfile)
contains a
[shell script](https://github.com/ivandeex/rclone/blob/stream-reset/stream-reset/test.sh)
that repeateadly runs `restic prune` with rclone instrumented
to reproduce the problem until it finds the relevant error message in logs.

I have added some debug messages (https://github.com/ivandeex/golang-net/commits/stream-reset)
to the latest golang's `net.http2` https://github.com/golang/net/tree/release-branch.go1.15
and instrumented latest
restic 0.10 (https://github.com/ivandeex/restic/commits/stream-reset)
and rclone (https://github.com/ivandeex/rclone/commits/stream-reset)
to use the version with debug.
The patched programs can use HTTP/2 over stdio pipe or local port
and HTTP/1.1 on local port for exchange, depending on a few
`RESTIC_RCLONE_xxx` environment variables.
See Dockerfile on how to build the binaries if you opt to not use docker.

You have to prepare a backup repository for tests.
I used a backup from one of my VPS boxes
with some 20 snapshots with total size about 30G.
For instance, you can prepare it as described in restic
documentation (https://restic.readthedocs.io/en/latest/030_preparing_a_new_repo.html#local):

```
mkdir -p ~/repository/repo
export RESTIC_REPOSITORY=~/repository/repo
export RESTIC_PASSWORD=secret123
restic init
restic backup /
restic backup /dir1
restic backup /dir2
```
The test script will run `restic prune`.
The more read/writes it does, the earlier you hit the issue.
I recommend to `restic forget` some snapshots before running the test:

```
restic snapshots
restic forget snapshot1
restic forget snapshot2
```

Make sure the mount `~/repository` has enough space
as the test script will create a full copy of `repo` into `repo.work`.

Please note that the last part of the directory name must be `repo`.

Now that repository is ready you can run dockerized test.
Create a directory for test logs and proceed.

## HTTP/2 Over Stdio Pipe

This exchange method is used by default between restic and rclone.

Note: the bind mount path `/path/to/repository` must not
include the last part of the name (it must always be `repo`),
the test script will add it on its own.

```
docker run -e num_loops=100 \
           -e RESTIC_RCLONE_PORT=0 \
           -e RESTIC_RCLONE_HTTP2=1 \
           -e RESTIC_PASSWORD=$RESTIC_PASSWORD \
           -v /path/to/repository:/repo \
           -v /path/to/test/logs:/test \
           --rm --name test -it \
           ivandeex/restic-stream-reset
```
After a few loops the test will hit the issue and stop.
You will find `restic-error.log` and `rclone-error.log` in the test directory.
Look for `ERROR` in the rclone log, then use snapshot name
and size to find relevant messages in the restic log,
then use http2 stream id to find relevant http2 debug messages.

Example log snippets
[rclone-err.log.snippet.txt](https://github.com/ivandeex/rclone/blob/stream-reset/stream-reset/snippets/rclone-err.log.snippet.txt)
and 
[restic-err.log.snippet.txt](https://github.com/ivandeex/rclone/blob/stream-reset/stream-reset/snippets/restic-err.log.snippet.txt)
prove the explanation above.

## HTTP/2 Over Loopback Socket

Set `RESTIC_RCLONE_PORT=12345`
changing media from stdio pipe to TCP/IP on local port
and run the test. The error still reproduces.

```
docker run -e num_loops=100 \
           -e RESTIC_RCLONE_PORT=12345 \
           -e RESTIC_RCLONE_HTTP2=1 \
           -e RESTIC_PASSWORD=$RESTIC_PASSWORD \
           -v /path/to/repository:/repo \
           -v /path/to/test/dir:/test \
           --rm --name test -it \
           ivandeex/restic-stream-reset
```

## HTTP/1.1 Over Loopback Socket

Change protocol from HTTP2 to HTTP1 (RESTIC_RCLONE_HTTP2=0) and run the test.
Keep the port on because HTTP1 cannot be used on stdio pipe.
The error disappears.

```
docker run -e num_loops=100 \
           -e RESTIC_RCLONE_PORT=12345 \
           -e RESTIC_RCLONE_HTTP2=0 \
           -e RESTIC_PASSWORD=$RESTIC_PASSWORD \
           -v /path/to/repository:/repo \
           -v /path/to/test/logs:/test \
           --rm --name test -it \
           ivandeex/restic-stream-reset
```

## Distribution Of Delays Till HTTP2 EOF

Now revert to HTTP2 (RESTIC_RCLONE_HTTP2=1) over stdio pipe (RESTIC_RCLONE_PORT=0),
enable code path that fixes the problem (RESTIC_RCLONE_DRAIN=1)
and run the test. This will eliminate the error and let us estimate the length
of the critical interval between stream reset and the moment of EOF delivery.

```
docker run -e num_loops=5 \
           -e RESTIC_RCLONE_DRAIN=1 \
           -e RESTIC_RCLONE_PORT=0 \
           -e RESTIC_RCLONE_HTTP2=1 \
           -e RESTIC_PASSWORD=$RESTIC_PASSWORD \
           -v /path/to/repo:/repo \
           -v /path/to/test/dir:/test \
           --rm --name test -it \
           ivandeex/restic-stream-reset

```
Since restic now waits for EOF, there will be no errors anymore.
Also restic is instrumented to report the time to wait for EOF in the log.
The first 2-3 loops let restic warm up its cache so the last run numbers look natural.
When the test is done, run this command to obtain the delays:
```
grep 'rload drain' restic-noerr.log |awk '{print$7}' |grep -Eo '[0-9]+' |sort -rn |uniq -c
```
This returns lines where the second number is `delay` rounded to whole milliseconds
and the first one is the number of times this delay was hit. In my case it was:
```
    1 57
    1 25
    1 20
    2 18
    1 17
    2 13
    1 12
    4 11
    5 10
    7 9
   14 8
   15 7
   33 6
   36 5
   84 4
  177 3
  525 2
 2028 1
11758 0
```
Thus, the critical delay is `<1ms` in `80%`, `1-2ms` in `18%`, `>2ms` in `2%` cases.

## Comparing synchronous vs async drain methods

Run 100 loops (more than enough for averaging) with _asynchronous_ drain and save statistics:
```
docker run -e RESTIC_RCLONE_DRAIN_SYNC=0 \
           -e num_loops=100 \
           -e show_stats=1 \
           -e debugging=0
           -e RESTIC_RCLONE_DRAIN=1 \
           -e RESTIC_RCLONE_PORT=0 \
           -e RESTIC_RCLONE_HTTP2=1 \
           -e RESTIC_PASSWORD=$RESTIC_PASSWORD \
           -v /path/to/repo:/repo \
           -v /path/to/test/dir:/test \
           --rm --name test -it \
           ivandeex/restic-stream-reset
```

Every line in the `stats` file has four numbers:
```
iteration_number total_load_time load_speed total_load_size
```
where total load time is whole milliseconds, total load size is megabytes (rounded), load speed is ratio of time to size expressed as `milliseconds per megabyte`.

Calculate average load time and speed:
```
awk '{st+=$2;sbw+=$3;n+=1} END{printf("avg_time=%d avg_speed=%d num_loops=%d\n",st/n,sbw/n,n)}' stats.log
```

Then re-run with _synchronous_ drain, save statistics, find average time and speed:
```
docker run -e RESTIC_RCLONE_DRAIN_SYNC=1 \
           -e num_loops=100 \
           ...
awk '{st+=$2;sbw+=$3;n+=1} END{printf("avg_time=%d avg_speed=%d num_loops=%d\n",st/n,sbw/n,n)}' stats.log

```

For my 30G repository I have on average for 100 loops:
```
async drain: time: 55871 msec, speed: 1790 msec/MB
synchronous: time: 56930 msec, speed: 1824 msec/MB
```

Load time per megabyte (aka speed) for sequential drain is 34ms (2%) more than in async case, on average.
Total load time per run in sequential drain is 1sec (2%) more than in async case, on average.

Conclusion: goroutine has a slight 2% imrovement.
