FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y python3 tmux git gdb python3-pip && python3 -m pip install pipenv
RUN git clone https://github.com/longld/peda.git ~/peda && echo "source ~/peda/peda.py" >> ~/.gdbinit
RUN mkdir solve

COPY Pipfile /solve
RUN cd solve && pipenv install --python /usr/bin/python3

COPY challenge /solve
COPY solve.py /solve

WORKDIR /solve

COPY entry.sh /solve
RUN chmod +x entry.sh

CMD [ "tmux", "new-session", "./entry.sh" ]