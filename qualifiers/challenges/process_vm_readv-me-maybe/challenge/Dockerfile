FROM livectf/livectf:quals-nsjail as base

# Space-separated list of required packages
# Installing GDB is apparently necessary to get my solve script to work??
ARG REQUIRED_PACKAGES="libseccomp2 build-essential libseccomp-dev gdb"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

FROM base as build

COPY build.sh /build.sh
COPY src/ /src/
RUN mkdir /build /handout
RUN cd / && chmod +x /build.sh && /build.sh

COPY dist.Dockerfile /handout/Dockerfile
COPY config.toml /handout/
RUN tar -czf /handout.tar.gz /handout

FROM base as run

COPY --from=build /handout/challenge /home/livectf/
COPY --from=build /handout.tar.gz /handout.tar.gz
COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
