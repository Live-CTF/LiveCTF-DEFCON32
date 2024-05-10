FROM python:slim-bullseye

ARG DEBIAN_FRONTEND=noninteractive

RUN pip install pwntools
RUN apt-get update \
    && apt-get install -y --no-install-recommends ruby binutils-multiarch \
    && rm -rf /var/lib/apt/lists/*
RUN gem install one_gadget

COPY handout.tar.gz /handout.tar.gz
RUN mkdir /handout && tar xzf /handout.tar.gz
COPY solve.py /

WORKDIR /
CMD ["python3", "solve.py"]
