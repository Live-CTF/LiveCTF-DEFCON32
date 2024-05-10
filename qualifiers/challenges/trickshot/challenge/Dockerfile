FROM livectf/livectf:quals-nsjail as base

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i -e '/path: /s/"\/home\/livectf\/challenge"/"\/usr\/bin\/python3"/' nsjail.conf
RUN sed -i -e '/arg: /s/""/"\/home\/livectf\/challenge.py"/' nsjail.conf

FROM base as build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="build-essential python3 python3-pip"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

COPY build.sh /build.sh
COPY src/ /src/
RUN mkdir /build /handout
RUN cd / && /build.sh

COPY dist.Dockerfile /handout/Dockerfile
COPY config.toml /handout/
RUN tar -czf /handout.tar.gz /handout

FROM base as run

COPY --from=build /build/trickshot /home/livectf/
COPY --from=build /src/challenge.py /home/livectf/
COPY --from=build /handout.tar.gz /handout.tar.gz
COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
