FROM livectf/livectf:quals-exploit

COPY solve-template.py /solve.py
COPY challenge libc.so.6 /

WORKDIR /
CMD ["python3", "solve.py"]
