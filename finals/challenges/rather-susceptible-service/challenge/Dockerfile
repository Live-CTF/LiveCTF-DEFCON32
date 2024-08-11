FROM livectf/livectf:finals-nsjail as base

FROM base as run

ARG REQUIRED_PACKAGES="python3 python3-pip"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

COPY --chown=root:flag --chmod=440 config.toml /home/livectf/.config.toml

RUN python3 -m pip install flask requests rss-parser

COPY src/server.py /home/livectf/server.py
COPY src/templates /home/livectf/templates
COPY src/static /home/livectf/static
COPY nsjail.conf /home/livectf/

COPY --chown=root:flag --chmod=440 config.toml /home/livectf/.config.toml

COPY --chmod=755 package.sh /
RUN cd / && /package.sh && rm /package.sh
