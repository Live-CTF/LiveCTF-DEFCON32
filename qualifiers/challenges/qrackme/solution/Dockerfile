FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends build-essential python3 python3-pip binutils-multiarch gcc-multilib tmux wget tar \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-10.90.19845/DynamoRIO-Linux-10.90.19845.tar.gz \
    && tar xf /DynamoRIO-Linux-10.90.19845.tar.gz \
    && rm /DynamoRIO-Linux-10.90.19845.tar.gz

RUN python3 -m pip install pwntools

COPY solve.py /

WORKDIR /
CMD ["python3", "-u", "solve.py"]
