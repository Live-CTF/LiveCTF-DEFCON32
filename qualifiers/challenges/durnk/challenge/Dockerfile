FROM livectf/livectf:quals-socat as base

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates

RUN mkdir -pm755 /etc/apt/keyrings \
    && wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/bullseye/winehq-bullseye.sources

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends winehq-stable xvfb xauth \
    && rm -rf /var/lib/apt/lists/*

FROM base as build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="build-essential mingw-w64"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES}

COPY build.sh /build.sh
COPY src/ /src/
RUN mkdir /build /handout

RUN cd / && chmod +x /build.sh && /build.sh

RUN cp /build/challenge /handout/challenge
COPY run.sh /handout/run.sh
COPY wine.reg /handout/wine.reg
COPY dist.Dockerfile /handout/Dockerfile
COPY config.toml /handout/
RUN tar -czf /handout.tar.gz /handout

FROM base as run

ARG DEBIAN_FRONTEND=noninteractive

COPY --from=build /handout/wine.reg /tmp/
RUN wine regedit.exe /tmp/wine.reg
COPY --from=build /build/challenge /home/livectf/
COPY --from=build /build/challenge.exe /home/livectf/
COPY --from=build /handout.tar.gz /handout.tar.gz
COPY --chown=root:flag config.toml /home/livectf/.config.toml
COPY --from=build /handout/run.sh /home/livectf/run.sh
RUN chmod 440 /home/livectf/.config.toml
RUN chmod +x /home/livectf/challenge /home/livectf/run.sh
