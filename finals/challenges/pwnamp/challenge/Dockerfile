FROM livectf/livectf:finals-nsjail as base

FROM base as build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="build-essential"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES}

RUN mkdir /build
WORKDIR /build
COPY src ./src
COPY --chmod=755 build.sh .
RUN ./build.sh

FROM base as run

COPY --from=build --chmod=755 /build/output/challenge /home/livectf/
COPY --chown=root:flag --chmod=440 config.toml /home/livectf/.config.toml
COPY nsjail.conf /home/livectf/

COPY --chmod=755 package.sh /
RUN cd / && /package.sh && rm /package.sh
