FROM docker:27-dind

# 1. Install dependencies
RUN apk add --no-cache git bash curl python3 nodejs libgcc libstdc++ gcompat ripgrep

# 2. Manual installation to a standard location
RUN curl -fsSL "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/2.1.59/linux-x64-musl/claude" -o /usr/bin/claude && \
    chmod +x /usr/bin/claude

# 3. Fix the library loader for Alpine
RUN ln -sf /lib/libc.musl-x86_64.so.1 /lib/ld-linux-x86-64.so.2

# 4. Verify during build
RUN /usr/bin/claude --version

ENV DOCKER_DRIVER=overlay2
EXPOSE 2375 2376