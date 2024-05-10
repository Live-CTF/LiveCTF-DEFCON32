FROM livectf/livectf:quals-exploit
WORKDIR /exp
RUN (python3 -c '__import__("os").write(1, __import__("requests").get("https://play.livectf.com/api/challenges/6/download").content)' | tar xvzf -) || true
COPY ./ ./
RUN chmod +x ./entrypoint
CMD ./entrypoint
