FROM livectf/livectf:quals-exploit

RUN python3 -m pip install angr

COPY solve.py /solve.py
COPY auto.py /auto.py

WORKDIR /
CMD ["python3", "solve.py"]
