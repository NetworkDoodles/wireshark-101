# The lab's dev container: containerlab's Docker-in-Docker image plus the checker's Python venv and the tshark wrapper.
# The venv is built here, in the image, so it's ready from the first second.
FROM ghcr.io/srl-labs/containerlab/devcontainer-dind-slim:0.83.0

USER vscode
ENV VENV=/home/vscode/.venvs/lab
ENV PATH=/home/vscode/.venvs/lab/bin:$PATH
COPY --chown=vscode:vscode requirements.txt /tmp/lab/
# .ok records which requirements were installed (the same hash `make setup` checks), so the first start
# doesn't reinstall them.
RUN uv venv -q --python 3.13 "$VENV" \
 && uv pip install -q --python "$VENV/bin/python" -r /tmp/lab/requirements.txt \
 && cd /tmp/lab && python3 -c "import hashlib,sys; print(hashlib.sha256(b''.join(open(f,'rb').read() for f in sys.argv[1:])).hexdigest()[:16])" requirements.txt > "$VENV/.ok"

# code-server reads its own settings, not devcontainer.json's.
COPY --chown=vscode:vscode .devcontainer/code-server-settings.json /home/vscode/.local/share/code-server/User/settings.json

# tshark runs from the lab's tool image (tshark 4.6; Debian here has only 4.0): this wrapper makes `tshark`
# work in any terminal, on any file under /workspaces.
USER root
COPY bin/tshark /usr/local/bin/tshark
RUN chmod 755 /usr/local/bin/tshark
USER vscode
