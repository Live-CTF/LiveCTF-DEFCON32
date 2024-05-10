FROM docker.io/rust:slim-bookworm as chef
RUN cargo install cargo-chef
WORKDIR /usr/src/livectf

FROM chef as planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as dependencies
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y pkg-config libssl-dev libpq-dev jq \
    && rm -rf /var/lib/apt/lists/*

ARG CHEF_FLAGS="--release"
COPY --from=planner /usr/src/livectf/recipe.json recipe.json
RUN cargo chef cook ${CHEF_FLAGS} --recipe-path recipe.json
RUN mkdir build
COPY . .

FROM dependencies as challenge-api-builder
ARG BUILD_FLAGS="--release"
RUN export BIN_PATH=$(cargo build --bin challenge-api ${BUILD_FLAGS} --message-format=json | jq -s -r '.[] | select(.target.name=="challenge-api" and .reason=="compiler-artifact").executable') && ln -s "$BIN_PATH" "build/"

FROM dependencies as exploit-builder-builder
ARG BUILD_FLAGS="--release"
RUN export BIN_PATH=$(cargo build --bin exploit-builder ${BUILD_FLAGS} --message-format=json | jq -s -r '.[] | select(.target.name=="exploit-builder" and .reason=="compiler-artifact").executable') && ln -s "$BIN_PATH" "build/"

FROM dependencies as exploit-runner-builder
ARG BUILD_FLAGS="--release"
RUN export BIN_PATH=$(cargo build --bin exploit-runner ${BUILD_FLAGS} --message-format=json | jq -s -r '.[] | select(.target.name=="exploit-runner" and .reason=="compiler-artifact").executable') && ln -s "$BIN_PATH" "build/"

FROM docker.io/debian:bookworm-slim as challenge-api
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=challenge-api-builder /usr/src/livectf/build/challenge-api /usr/local/bin/challenge-api
CMD ["challenge-api"]

FROM docker.io/debian:bookworm-slim as exploit-builder
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y libpq5 ca-certificates curl gnupg lsb-release

RUN apt-get update \
    && apt-get install -y fuse-overlayfs podman \
    && rm -rf /var/lib/apt/lists/*

COPY --from=exploit-builder-builder /usr/src/livectf/build/exploit-builder /usr/local/bin/exploit-builder
RUN mkdir -p /tmp/builds

RUN useradd podman -m -u 1000; echo podman:10000:5000 > /etc/subuid; echo podman:10000:5000 > /etc/subgid;
#VOLUME /var/lib/containers
#VOLUME /home/podman/.local/share/containers
COPY configs/containers.conf /etc/containers/containers.conf
COPY configs/storage.conf /etc/containers/storage.conf
COPY configs/podman-containers.conf /etc/containers/podman-containers.conf
RUN mkdir -p /var/lib/shared/overlay-images /var/lib/shared/overlay-layers /var/lib/shared/vfs-images /var/lib/shared/vfs-layers; touch /var/lib/shared/overlay-images/images.lock; touch /var/lib/shared/overlay-layers/layers.lock; touch /var/lib/shared/vfs-images/images.lock; touch /var/lib/shared/vfs-layers/layers.lock
ENV _CONTAINERS_USERNS_CONFIGURED=""
CMD ["exploit-builder"]

FROM docker.io/debian:bookworm-slim as exploit-runner
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y libpq5 ca-certificates curl gnupg lsb-release

RUN apt-get update \
    && apt-get install -y ca-certificates fuse-overlayfs podman \
    && rm -rf /var/lib/apt/lists/*

COPY --from=exploit-runner-builder /usr/src/livectf/build/exploit-runner /usr/local/bin/exploit-runner

RUN useradd podman -m -u 1000; echo podman:10000:5000 > /etc/subuid; echo podman:10000:5000 > /etc/subgid;
#VOLUME /var/lib/containers
#VOLUME /home/podman/.local/share/containers
COPY configs/containers.conf /etc/containers/containers.conf
COPY configs/storage.conf /etc/containers/storage.conf
COPY configs/podman-containers.conf /etc/containers/podman-containers.conf
RUN mkdir -p /var/lib/shared/overlay-images /var/lib/shared/overlay-layers /var/lib/shared/vfs-images /var/lib/shared/vfs-layers; touch /var/lib/shared/overlay-images/images.lock; touch /var/lib/shared/overlay-layers/layers.lock; touch /var/lib/shared/vfs-images/images.lock; touch /var/lib/shared/vfs-layers/layers.lock
ENV _CONTAINERS_USERNS_CONFIGURED=""
CMD ["exploit-runner"]
