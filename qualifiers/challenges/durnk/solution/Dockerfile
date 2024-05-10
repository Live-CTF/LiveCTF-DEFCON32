FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential python3 python3-pip binutils-multiarch \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install pwntools

COPY handout.tar.gz /handout.tar.gz
RUN mkdir /handout && tar xzf /handout.tar.gz
COPY solve.py /

WORKDIR /
CMD ["python3", "solve.py", "--network"]
