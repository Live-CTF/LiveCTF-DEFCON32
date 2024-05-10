FROM livectf/livectf:quals-exploit

RUN apt-get update && apt-get install -y nasm && pip install ptrlib


COPY solve-template.py /solve.py

WORKDIR /
CMD ["python3", "solve.py"]
