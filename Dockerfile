# Excalibur Docker Image
# Lightweight penetration testing environment with Excalibur

FROM ubuntu:24.04

LABEL description="Excalibur - AI-Powered Penetration Testing Agent"
LABEL version="1.0.0"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    # Build essentials
    build-essential \
    software-properties-common \
    ca-certificates \
    gnupg \
    # Python
    python3.12 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Essential pentesting tools
    nmap \
    netcat-openbsd \
    curl \
    wget \
    git \
    sudo \
    # Network utilities
    net-tools \
    dnsutils \
    whois \
    # VPN (for HackTheBox/TryHackMe connectivity)
    openvpn \
    # Text processing
    jq \
    ripgrep \
    # Terminal
    tmux \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# Install additional security/pentesting tools
RUN apt-get update && \
    apt-get install -y \
    # Web fuzzing/brute-forcing
    gobuster \
    dirb \
    # Web vulnerability scanning
    nikto \
    # SQL injection
    sqlmap \
    # Credential attacks
    hydra \
    john \
    # Network analysis
    tcpdump \
    # Additional utilities
    sshpass \
    proxychains4 \
    socat \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Install ffuf (architecture-aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then FFUF_ARCH="linux_amd64"; \
    elif [ "$ARCH" = "arm64" ]; then FFUF_ARCH="linux_arm64"; \
    else echo "Unsupported architecture: $ARCH" && exit 1; fi && \
    wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_${FFUF_ARCH}.tar.gz" -O /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp && \
    mv /tmp/ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && \
    rm /tmp/ffuf.tar.gz

# Download common wordlists from SecLists with retry logic
# Falls back gracefully if downloads fail (users can download manually)
RUN mkdir -p /usr/share/wordlists && \
    (curl -fsSL --retry 3 --retry-delay 5 \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -o /usr/share/wordlists/common.txt || echo "Warning: Failed to download common.txt") && \
    (curl -fsSL --retry 3 --retry-delay 5 \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
        -o /usr/share/wordlists/raft-medium-directories.txt || echo "Warning: Failed to download raft-medium-directories.txt") && \
    (curl -fsSL --retry 3 --retry-delay 5 \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt" \
        -o /usr/share/wordlists/top-10000-passwords.txt || echo "Warning: Failed to download top-10000-passwords.txt")

# Install linpeas/winpeas scripts for privilege escalation enumeration
RUN mkdir -p /opt/peass && \
    wget -q https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -O /opt/peass/linpeas.sh && \
    chmod +x /opt/peass/linpeas.sh

# Install Node.js v20 (required for Claude Code CLI)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Remove EXTERNALLY-MANAGED marker to allow pip/poetry in Docker
# Also remove system Python packages that conflict with Poetry dependencies
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
    apt-get remove -y python3-cryptography && \
    apt-get autoremove -y

# Install Claude Code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Install Claude Code Router globally (for OpenRouter support)
RUN npm install -g @musistudio/claude-code-router

# Create non-root user
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up working directories (including ccr config)
RUN mkdir -p /workspace /app /home/pentester/.claude /home/pentester/.claude-code-router && \
    chown -R pentester:pentester /workspace /app /home/pentester/.claude /home/pentester/.claude-code-router

# Switch to pentester user
USER pentester
WORKDIR /app

# Install Poetry for Python dependency management
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    echo 'export PATH="/home/pentester/.local/bin:$PATH"' >> /home/pentester/.bashrc

ENV PATH="/home/pentester/.local/bin:$PATH"

# Copy project files
COPY --chown=pentester:pentester pyproject.toml README.md /app/
COPY --chown=pentester:pentester excalibur/ /app/excalibur/
COPY --chown=pentester:pentester scripts/entrypoint.sh /home/pentester/entrypoint.sh
COPY --chown=pentester:pentester scripts/ccr-config-template.json /app/scripts/ccr-config-template.json

# Install Python dependencies as root to system Python
# Allow pip to override system packages in Docker
ENV PIP_BREAK_SYSTEM_PACKAGES=1
USER root
RUN poetry config virtualenvs.create false && \
    poetry install --only main && \
    chmod +x /home/pentester/entrypoint.sh

# Switch back to pentester user for runtime
USER pentester

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default working directory for penetration tests
WORKDIR /workspace

# Use entrypoint script for auth setup
ENTRYPOINT ["/home/pentester/entrypoint.sh"]

# Default command - interactive bash
# Users can run: excalibur --target X
CMD ["/bin/bash"]
