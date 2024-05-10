FROM livectf/livectf:quals-exploit
COPY solve.py /
RUN pip3 install pwntools
WORKDIR /
CMD ["python3", "solve.py"]
