FROM livectf/livectf:quals-nsjail

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3 python3-cryptography"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

COPY challenge /home/livectf/
COPY backdoor.py /home/livectf/
COPY gen.py /home/livectf/
RUN cd /home/livectf/ && python3 gen.py

COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
