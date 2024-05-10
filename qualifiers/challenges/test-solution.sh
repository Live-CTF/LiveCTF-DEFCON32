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
if docker container inspect "livectf_TEST_$1_exploit" > /dev/null 2>&1; then
    docker container stop "livectf_TEST_$1_exploit"
fi
if docker network inspect "livectf_TEST_$1_network" > /dev/null 2>&1; then
    docker network rm "livectf_TEST_$1_network"
fi

docker network create --internal --driver bridge "livectf_TEST_$1_network"
CONTAINER=$(docker run -d --rm --privileged --network "livectf_TEST_$1_network" -e "FLAG=LiveCTF{test-flag}" --name "livectf_TEST_$1" "livectf:$1")
docker run --rm --network "livectf_TEST_$1_network" -it -e "HOST=livectf_TEST_$1" --name "livectf_TEST_$1_exploit" "livectf:$1_exploit"
docker stop "$CONTAINER"
docker network rm "livectf_TEST_$1_network"

cd - # $TEMP_DIR

rm -rf "$TEMP_DIR"
