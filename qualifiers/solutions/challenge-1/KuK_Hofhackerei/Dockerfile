FROM livectf/livectf:quals-exploit

COPY solve.py /solve.py

RUN python3 -m pip install pycryptodome

WORKDIR /
CMD ["python3", "solve.py"]
