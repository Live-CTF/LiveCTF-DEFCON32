FROM livectf/livectf:quals-exploit

COPY solve.py /solve.py
COPY challenge_patched /challenge_patched
COPY libc.so.6 /libc.so.6

WORKDIR /
CMD ["python3", "solve.py"]
