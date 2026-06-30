# Claude Code secure development sandbox.
# All development for this project runs INSIDE this container. The host
# filesystem/credentials are not mounted (see devcontainer.json), and egress
# is restricted to an allowlist by init-firewall.sh at container start.
#
# NOTE: tool binaries (kubectl/helm/k3s/nerdctl) are downloaded at BUILD time,
# i.e. before the runtime firewall applies. The firewall only constrains
# runtime egress.
# Debian trixie base: ships git 2.47 (jj requires git >= 2.41; bookworm's 2.39
# is too old and breaks `jj git fetch` with "unrecognized option: porcelain").
FROM node:24-trixie@sha256:5ac1f09047e215d1e4df7fbdf95ff86ca14a35632380b6672d6c9c62d5ac3800

ARG KUBECTL_VERSION=v1.31.4
ARG HELM_VERSION=v3.16.3
ARG K3S_VERSION=v1.31.4+k3s1
ARG NERDCTL_VERSION=2.0.2
ARG JJ_VERSION=0.42.0
ARG TARGETARCH=amd64

# Base tooling + firewall deps (iptables/ipset) + k3s/containerd runtime deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl jq git sudo less vim \
      openssh-client \
      iptables ipset iproute2 dnsutils \
      uidmap fuse-overlayfs \
    && rm -rf /var/lib/apt/lists/*

# GitHub CLI (optional, used for git/PR workflows from inside the sandbox).
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# kubectl
RUN curl -fsSLo /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
    && chmod +x /usr/local/bin/kubectl

# helm
RUN curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz" \
      | tar -xz -C /tmp \
    && mv "/tmp/linux-${TARGETARCH}/helm" /usr/local/bin/helm \
    && rm -rf "/tmp/linux-${TARGETARCH}"

# k3s (single binary, embedded containerd — NOT docker-in-docker)
RUN curl -fsSLo /usr/local/bin/k3s \
      "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s$( [ "${TARGETARCH}" = "arm64" ] && echo "-arm64" )" \
    && chmod +x /usr/local/bin/k3s

# Pre-load k3s system images (pause/coredns/etc.). k3s auto-imports tarballs in
# /var/lib/rancher/k3s/agent/images/ at startup, so Pod sandboxes can be created
# WITHOUT pulling from docker.io at runtime (Docker Hub moved blob delivery to a
# CloudFront host with volatile IPs that the egress allowlist can't track well).
# Build-time download — the runtime firewall is not yet applied.
RUN mkdir -p /var/lib/rancher/k3s/agent/images \
    && curl -fsSL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s-airgap-images-${TARGETARCH}.tar.gz" \
       -o /var/lib/rancher/k3s/agent/images/k3s-airgap.tar.gz

# nerdctl (full bundle: nerdctl + buildkit + containerd) for building the app
# image without a docker daemon, then `ctr images import` into k3s.
RUN curl -fsSL "https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-full-${NERDCTL_VERSION}-linux-${TARGETARCH}.tar.gz" \
      | tar -xz -C /usr/local

# jj (Jujutsu) — version control used for this project instead of git.
# The release tarball contains ./jj plus LICENSE/README, so extract to a temp
# dir and move just the binary.
RUN JJ_ARCH="$( [ "${TARGETARCH}" = "arm64" ] && echo aarch64 || echo x86_64 )" \
    && mkdir -p /tmp/jjdl \
    && curl -fsSL "https://github.com/jj-vcs/jj/releases/download/v${JJ_VERSION}/jj-v${JJ_VERSION}-${JJ_ARCH}-unknown-linux-musl.tar.gz" \
      | tar -xz -C /tmp/jjdl \
    && mv /tmp/jjdl/jj /usr/local/bin/jj \
    && chmod +x /usr/local/bin/jj \
    && rm -rf /tmp/jjdl

# Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code@latest

# Enforce the built-in sandbox (defense-in-depth) only INSIDE this container.
RUN mkdir -p /etc/claude-code
COPY managed-settings.json /etc/claude-code/managed-settings.json

# Firewall + cgroup-init scripts + passwordless sudo only for them (k3s startup
# needs root, and cgroup v2 nesting must be set up as root before k3s starts).
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
COPY k3s-cgroup-init.sh /usr/local/bin/k3s-cgroup-init.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/k3s-cgroup-init.sh \
    && echo "node ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh, /usr/local/bin/k3s-cgroup-init.sh, /usr/local/bin/k3s, /usr/local/bin/nerdctl, /usr/local/bin/ctr" \
      > /etc/sudoers.d/sandbox \
    && chmod 0440 /etc/sudoers.d/sandbox

# Trust GitHub's SSH host key at build time so `git`/`jj` push over SSH (using
# VS Code's forwarded SSH agent — no keys mounted, no PAT) works without an
# interactive host-key prompt. accept-new covers key rotation gracefully.
RUN ssh-keyscan -t rsa,ecdsa,ed25519 github.com >> /etc/ssh/ssh_known_hosts 2>/dev/null \
    && printf 'Host github.com\n    StrictHostKeyChecking accept-new\n' >> /etc/ssh/ssh_config

# Pre-create config dirs owned by `node`. The devcontainer mounts named volumes
# at ~/.claude (Claude auth) and ~/.config/gh (gh auth) to persist across
# rebuilds; if the dir does not exist in the image, Docker initialises the
# (root-owned) volume mountpoint and the node user cannot write — so auth is
# lost on every rebuild.
RUN mkdir -p /home/node/.claude /home/node/.config/gh \
    && chown -R node:node /home/node/.claude /home/node/.config

ENV DEVCONTAINER=true \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    KUBECONFIG=/home/node/.kube/config

USER node
WORKDIR /workspace
