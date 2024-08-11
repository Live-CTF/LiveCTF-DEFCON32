FROM python:slim-bullseye

ARG DEBIAN_FRONTEND=noninteractive

RUN pip install pwntools

COPY handout.tar.gz /handout.tar.gz
RUN mkdir /handout && tar xzf /handout.tar.gz
COPY solve.py /

WORKDIR /
CMD ["python3", "solve.py"]
