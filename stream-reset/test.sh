#!/bin/bash

export RESTIC_RCLONE_DRAIN=${RESTIC_RCLONE_DRAIN:-0}
export RESTIC_RCLONE_DRAIN_SYNC=${RESTIC_RCLONE_DRAIN_SYNC:-0}
export RESTIC_RCLONE_PORT=${RESTIC_RCLONE_PORT:-12345}
export RESTIC_RCLONE_HTTP2=${RESTIC_RCLONE_HTTP2:-1}
export RCLONE_HIDE_STREAM_RESET=${RCLONE_HIDE_STREAM_RESET:-0}
export RESTIC_REPOSITORY=${RESTIC_REPOSITORY:-rclone:repo1:}

bindir=${bindir:-~/bin}
logdir=${logdir:-~/http2}
repodir=${repodir:-~/repo}
num_loops=${num_loops:-30}

verbose=${verbose:-0}
debugging=${debugging:-1}
show_stats=${show_stats:-0}

detect_errors=1
detect_delays=0
rebuild=0

restic=$bindir/restic
rclone=$bindir/rclone

[[ $verbose = 1 ]] && set -x

# build binaries
if [[ $rebuild = 1 ]]; then
    mkdir -p "$bindir"
    cd ~/restic || exit 1
    go build -o "$restic" ./cmd/restic || exit 1
    cd ~/rclone || exit 1
    go build -o "$rclone" . || exit 1
fi
cd "$logdir" || exit 1

# restic init
# for dir in <random_dirs>; do restic backup $dir; done
# restic forget <random_snapshots>
# echo backup repository
# rsync -a --delete ~/http/repo.1/ ~/http/repo.2/

if [[ $debugging = 1 ]]; then
    export RESTIC_LOG_FILE=$logdir/restic.log
    export RCLONE_LOG_FILE=$logdir/rclone.log
    export RCLONE_VERBOSE=1
else
    export RESTIC_LOG_FILE=""
    export RCLONE_LOG_FILE=""
    unset RCLONE_VERBOSE
fi

# purge logs from previous runs
rm -f ./*.log

# loop until problem reveals itself
for iter in $(seq "$num_loops"); do
    echo "=== loop $iter at $(date) ==="
    echo "$iter" > iter

    # restore repo in case user did "restic forget" before test
    rsync -a --delete "$repodir/repo/" "$repodir/repo.work/"
    sync
    sleep 2  # let disk io calm down

    # remove old logs, ensure empty logs in case debugging is 0
    rm -f ./output.log ./restic.log ./rclone.log
    touch ./output.log ./restic.log ./rclone.log

    $restic prune &>./output.log
    sleep 2  # let rclone exit

    errors=$(grep -c ERROR ./rclone.log)
    if [[ $errors -ge 1 ]] && [[ $detect_errors = 1 ]]; then
        echo "!!! found $errors errors at loop $iter"
        break
    fi

    delays=$(grep drain ./restic.log | grep -v 0ms | grep -cE '[123].ms')
    if [[ $delays -ge 1 ]] && [[ $detect_delays = 1 ]]; then
        echo "!!! found $delays delays at loop $iter"
        break
    fi

    stats=$(awk '/^LoadStats/{print$2,$3,$4}' ./output.log)
    if [[ $show_stats = 1 ]] && [[ $stats ]]; then
        echo "$iter $stats" | tee -a stats.log
    fi

    # save results without error
    mv -f ./output.log ./output-noerr.log
    mv -f ./rclone.log ./rclone-noerr.log
    mv -f ./restic.log ./restic-noerr.log
done
echo "ran $iter loops, found $errors errors"

# dump error results
test -f ./output.log && mv -f ./output.log ./output-error.log
test -f ./rclone.log && mv -f ./rclone.log ./rclone-error.log
test -f ./restic.log && mv -f ./restic.log ./restic-error.log
dos2unix ./*.log 2>/dev/null ||:

# done
