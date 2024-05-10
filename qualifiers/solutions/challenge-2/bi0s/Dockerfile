FROM livectf/livectf:quals-exploit
COPY solve.py /
COPY libc.so.6 /
COPY challenge /
WORKDIR /
CMD ["python3", "solve.py"]