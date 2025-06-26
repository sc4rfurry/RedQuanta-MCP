# Multi-stage build for RedQuanta MCP
# Stage 1: Build the application
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json pnpm-lock.yaml* ./
COPY pnpm-workspace.yaml ./

# Install pnpm and dependencies
RUN npm install -g pnpm@8
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build the application
RUN pnpm build

# Stage 2: Security scanner tools base
FROM kalilinux/kali-rolling AS tools

# Update and install all penetration testing tools
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    gobuster \
    nikto \
    sqlmap \
    john \
    hydra \
    zaproxy \
    metasploit-framework \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install FFUF
RUN curl -L https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin/

# Create wordlists directory and download common wordlists
RUN mkdir -p /opt/wordlists
RUN wget -O /opt/wordlists/dir.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
RUN wget -O /opt/wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

# Stage 3: Production runtime
FROM node:20-alpine AS runtime

# Install security and runtime dependencies
RUN apk add --no-cache \
    dumb-init \
    su-exec \
    docker \
    && addgroup -g 1001 -S redquanta \
    && adduser -S -D -H -u 1001 -s /sbin/nologin -G redquanta redquanta

# Create application directories
WORKDIR /app
RUN mkdir -p /opt/redquanta/vol /app/logs /app/config /app/wordlists

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Copy tools from Kali stage
COPY --from=tools /usr/bin/nmap /usr/local/bin/
COPY --from=tools /usr/bin/masscan /usr/local/bin/
COPY --from=tools /usr/bin/gobuster /usr/local/bin/
COPY --from=tools /usr/bin/nikto /usr/local/bin/
COPY --from=tools /usr/bin/john /usr/local/bin/
COPY --from=tools /usr/bin/hydra /usr/local/bin/
COPY --from=tools /usr/local/bin/ffuf /usr/local/bin/
COPY --from=tools /opt/wordlists /app/wordlists/

# Copy configuration files
COPY config/ ./config/

# Set proper permissions
RUN chown -R redquanta:redquanta /app /opt/redquanta
RUN chmod +x /usr/local/bin/*

# Create non-root user for running tools
USER redquanta

# Expose MCP server port
EXPOSE 5891

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "fetch('http://localhost:5891/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Default command
CMD ["node", "dist/server.js", "--mode=rest", "--port=5891"]

# Labels for better maintainability
LABEL org.opencontainers.image.title="RedQuanta MCP"
LABEL org.opencontainers.image.description="Cross-platform, security-hardened MCP server for penetration testing"
LABEL org.opencontainers.image.version="0.3.0"
LABEL org.opencontainers.image.authors="RedQuanta Team"
LABEL org.opencontainers.image.licenses="MIT" 