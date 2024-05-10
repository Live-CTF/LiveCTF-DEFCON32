#!/bin/sh
set -e
set -x

HANDOUT="handouts/$1-handout.tar.gz"
TEMP_DIR=$(mktemp -d)
tar -xzf "$HANDOUT" -C "$TEMP_DIR"

cd $TEMP_DIR

if docker container inspect "livectf_TEST_$1" > /dev/null 2>&1; then
    docker container stop "livectf_TEST_$1"
fi

CONTAINER=$(docker run -d --rm --privileged -p 31337:31337 -e "FLAG=LiveCTF{test-flag}" --name "livectf_TEST_$1" "livectf:$1")

docker container logs --follow $CONTAINER &

(trap exit INT ; read REPLY)

kill -15 %1

docker stop "$CONTAINER"

cd - # $TEMP_DIR

rm -rf "$TEMP_DIR"
