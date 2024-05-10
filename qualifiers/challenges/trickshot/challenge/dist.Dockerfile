FROM livectf/livectf:quals-nsjail

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

COPY challenge.py /home/livectf/
COPY trickshot /home/livectf/

RUN sed -i -e '/path: /s/"\/home\/livectf\/challenge"/"\/usr\/bin\/python3"/' nsjail.conf
RUN sed -i -e '/arg: /s/""/"\/home\/livectf\/challenge.py"/' nsjail.conf

COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
