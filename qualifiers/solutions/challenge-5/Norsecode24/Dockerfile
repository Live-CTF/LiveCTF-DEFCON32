FROM livectf/livectf:quals-exploit

RUN ["pip", "install", "angr"]
COPY solve-template.py /solve.py
WORKDIR /
CMD ["python3", "solve.py"]
