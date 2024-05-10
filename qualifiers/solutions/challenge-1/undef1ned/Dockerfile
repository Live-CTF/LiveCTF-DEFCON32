FROM livectf/livectf:quals-exploit

# things for the crypto
RUN pip install pycryptodome

# only for pwn
COPY solve.py /
WORKDIR /
CMD ["python3", "solve.py"]
