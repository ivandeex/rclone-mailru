FROM golang:1.13

RUN cd /go && git clone -b stream-reset https://github.com/ivandeex/restic
RUN cd /go/restic && go build ./cmd/restic

RUN cd /go && git clone -b stream-reset https://github.com/ivandeex/rclone
RUN cd /go/rclone && go build .

FROM golang:1.13

RUN : \
 && apt-get -qqy update \
 && apt-get -qqy install rsync dos2unix \
 && apt-get clean && rm -rf /var/cache/apt/* \
 && mkdir -p /test /repo

COPY --from=0 /go/rclone/rclone /go/bin
VOLUME /repo
COPY rclone.conf /etc
ENV RCLONE_CONFIG /etc/rclone.conf

COPY --from=0 /go/restic/restic /go/bin
ENV RESTIC_REPOSITORY=rclone:repo1:
ENV RESTIC_PASSWORD=secret

COPY test.sh /go/bin
VOLUME /test

ENV bindir=/go/bin
ENV logdir=/test
ENV repodir=/repo
ENV num_loops=30
ENV verbose=0
ENV debugging=1
ENV show_stats=0

ENV RESTIC_RCLONE_DRAIN=0
ENV RESTIC_RCLONE_DRAIN_SYNC=0
ENV RESTIC_RCLONE_PORT=12345
ENV RESTIC_RCLONE_HTTP2=1
ENV RCLONE_HIDE_STREAM_RESET=0

WORKDIR /test
CMD test.sh
