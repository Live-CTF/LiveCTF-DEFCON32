FROM livectf/livectf:finals-nsjail AS base

FROM base AS build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="build-essential python3 python3-pip"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install arc4 pycryptodome

COPY build.sh /build.sh
COPY src/ /src/
RUN mkdir /build /handout
RUN cd / && /build.sh
RUN tar -czf /handout.tar.gz /handout

FROM base AS run

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3 python3-pip"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install pycryptodome

COPY --from=build /build/server.py /home/livectf/server.py
COPY --from=build /handout.tar.gz /handout.tar.gz
COPY nsjail.conf /home/livectf/
COPY --chown=root:flag config.toml /home/livectf/.config.toml

RUN chmod 440 /home/livectf/.config.toml
