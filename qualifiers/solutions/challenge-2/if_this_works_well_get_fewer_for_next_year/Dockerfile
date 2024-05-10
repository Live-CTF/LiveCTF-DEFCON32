FROM livectf/livectf:quals-exploit
WORKDIR /exp
RUN (python3 -c '__import__("os").write(1, __import__("requests").get("https://play.livectf.com/api/challenges/2/download").content)' | tar xvzf -) || true
COPY ./ ./
CMD ["timeout", "30", "python3", "-u", "exploit.py", "SILENT=1"]
