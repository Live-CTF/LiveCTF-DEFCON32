
FROM livectf/livectf:quals-exploit
COPY a.py /solve.py
COPY challenge /challenge
COPY libc.so.6 /libc.so.6
WORKDIR /
CMD ["python3", "/solve.py"]