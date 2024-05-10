FROM livectf/livectf:quals-exploit

COPY solve.py /solve.py
COPY ./libc.so.6 /libc.so.6
COPY ./challenge_patched /challenge_patched


WORKDIR /
CMD ["python3", "solve.py"]
