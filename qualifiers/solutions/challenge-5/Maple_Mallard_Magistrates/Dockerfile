FROM livectf/livectf:quals-exploit

COPY valgrind /usr/bin/valgrind
COPY valgrind.bin /usr/bin/valgrind.bin
COPY callgrind-x86-linux /usr/lib/x86_64-linux-gnu/valgrind/callgrind-x86-linux
COPY callgrind-amd64-linux /usr/lib/x86_64-linux-gnu/valgrind/callgrind-amd64-linux
COPY solve.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
