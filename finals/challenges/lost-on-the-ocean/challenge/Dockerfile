FROM livectf/livectf:finals-nsjail AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

FROM base AS build

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="build-essential curl libgpm-dev git"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

#RUN curl -L -o harbour.deb https://sourceforge.net/projects/harbour-project/files/binaries-linux-ubuntu/nightly/r2017-12-15-18_53_harbour_3.2.0-1_amd64.deb/download && \
#    apt-get update && dpkg -i harbour.deb; apt-get install -y -f && \
#    rm harbour.deb

RUN git clone https://github.com/harbour/core.git --depth 1 /harbour && \
    cd /harbour && \
    make -j && \
    make install


COPY build.sh /build.sh
COPY src/ /src/
RUN mkdir /build /handout
RUN cd / && chmod +x /build.sh && /build.sh
RUN tar -czf /handout.tar.gz /handout

FROM base AS run

COPY --from=build /build/crackme /home/livectf/
COPY --from=build /src/server.py /home/livectf/
COPY --from=build /handout.tar.gz /handout.tar.gz
COPY nsjail.conf /home/livectf/
RUN chmod +x /home/livectf/crackme

COPY --chown=root:flag config.toml /home/livectf/.config.toml

RUN chmod 440 /home/livectf/.config.toml
