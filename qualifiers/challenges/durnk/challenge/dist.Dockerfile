FROM livectf/livectf:quals-socat as base

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates
RUN mkdir -pm755 /etc/apt/keyrings \
    && wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/bullseye/winehq-bullseye.sources
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends winehq-stable xvfb xauth \
    && rm -rf /var/lib/apt/lists/*

COPY wine.reg /tmp/
RUN wine regedit.exe /tmp/wine.reg

COPY challenge /home/livectf/
COPY challenge.exe /home/livectf/
COPY run.sh /home/livectf/run.sh
RUN chmod +x /home/livectf/challenge /home/livectf/run.sh

COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
