FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py
COPY challenge /challenge
COPY ld-linux-x86-64.so.2 /ld-linux-x86-64.so.2
COPY libc.so.6 /libc.so.6

WORKDIR /
CMD ["python3", "solve.py"]
