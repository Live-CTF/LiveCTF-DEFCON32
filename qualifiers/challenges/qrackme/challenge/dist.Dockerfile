FROM livectf/livectf:quals-nsjail

# Space-separated list of required packages
ARG REQUIRED_PACKAGES="python3"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ${REQUIRED_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

COPY runner.py /home/livectf/
COPY bins/qrackme_0 /home/livectf/bins/
COPY bins/qrackme_1 /home/livectf/bins/
COPY bins/qrackme_2 /home/livectf/bins/
COPY bins/qrackme_3 /home/livectf/bins/
COPY bins/qrackme_4 /home/livectf/bins/

RUN sed -i -e '/path: /s/"\/home\/livectf\/challenge"/"\/usr\/bin\/python3"/' nsjail.conf
RUN sed -i -e '/arg: /s/""/"\/home\/livectf\/runner.py"/' nsjail.conf
RUN sed -i -e '/time_limit/s/120/240/' nsjail.conf

COPY --chown=root:flag config.toml /home/livectf/.config.toml
RUN chmod 440 /home/livectf/.config.toml
