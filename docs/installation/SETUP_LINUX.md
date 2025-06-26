# 🐧 RedQuanta MCP Linux Installation Guide

<p align="center">
  <img src="https://img.shields.io/badge/Linux-Fully%20Supported-brightgreen?style=for-the-badge&logo=linux" alt="Linux Support">
  <br/>
  <img src="https://img.shields.io/badge/Distros-Ubuntu%20%7C%20Debian%20%7C%20RHEL%20%7C%20Arch-blue?style=for-the-badge" alt="Distributions">
  <br/>
  <img src="https://img.shields.io/badge/Package%20Managers-apt%20%7C%20yum%20%7C%20pacman-orange?style=for-the-badge" alt="Package Managers">
</p>

<div align="center">

### 🚀 Complete Linux Setup for Professional Penetration Testing
*Comprehensive installation guide for all major Linux distributions*

</div>

---

## 🎯 Distribution Compatibility Matrix

| Distribution | Version | Package Manager | Installation Method | Status |
|:-------------|:--------|:----------------|:-------------------|:-------|
| **Ubuntu** | 20.04, 22.04, 24.04 | `apt` | Native packages + snap | ✅ **Fully Supported** |
| **Debian** | 11, 12 (Bookworm) | `apt` | Native packages | ✅ **Fully Supported** |
| **RHEL/CentOS** | 8, 9 | `yum`/`dnf` | EPEL + manual | ✅ **Supported** |
| **Fedora** | 38, 39, 40 | `dnf` | Native packages | ✅ **Supported** |
| **Arch Linux** | Rolling | `pacman` | AUR packages | ✅ **Community Supported** |
| **openSUSE** | Leap 15.x, Tumbleweed | `zypper` | Manual compilation | ⚠️ **Manual Setup Required** |
| **Kali Linux** | 2023.x, 2024.x | `apt` | Native packages | 🎯 **Optimized for Security** |

---

## ⚡ Quick Start (Ubuntu/Debian)

!!! tip "Recommended for Beginners"
    Ubuntu and Debian provide the smoothest installation experience with pre-built packages.

### 🚀 One-Command Installation

```bash title="Automated Installation"
# Download and run the automated installer
curl -fsSL https://raw.githubusercontent.com/sc4rfurry/RedQuanta-MCP/main/scripts/install-linux.sh | bash

# Or for a more controlled installation:
wget https://raw.githubusercontent.com/sc4rfurry/RedQuanta-MCP/main/scripts/install-linux.sh
chmod +x install-linux.sh
./install-linux.sh --interactive
```

### 📋 Manual Installation Steps

=== "Step 1: System Updates"

    ```bash title="Update Your System"
    # Ubuntu/Debian
    sudo apt update && sudo apt upgrade -y
    
    # Install build essentials
    sudo apt install -y curl wget git build-essential software-properties-common
    ```

=== "Step 2: Node.js"

    ```bash title="Install Node.js 20 LTS"
    # Install Node.js 20 LTS via NodeSource
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
    
    # Verify installation
    node --version  # Should show v20.x.x
    npm --version   # Should show 10.x.x
    ```

=== "Step 3: pnpm"

    ```bash title="Install pnpm Package Manager"
    # Install pnpm package manager
    curl -fsSL https://get.pnpm.io/install.sh | sh -
    source ~/.bashrc
    
    # Verify pnpm installation
    pnpm --version
    ```

=== "Step 4: RedQuanta"

    ```bash title="Clone and Build RedQuanta"
    # Clone the repository
    git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
    cd RedQuanta-MCP
    
    # Install dependencies
    pnpm install
    
    # Build the project
    pnpm build
    
    # Verify build
    ls -la dist/
    ```

=== "Step 5: Setup Environment"

    ```bash title="Create Jail Root Directory"
    # Create jail root with proper permissions
    sudo mkdir -p /opt/redquanta/vol
    sudo chown $USER:$USER /opt/redquanta/vol
    
    # Create subdirectories
    mkdir -p /opt/redquanta/vol/{tmp,wordlists,reports,uploads,downloads,configs,scripts,workspace}
    
    # Set environment variable
    echo 'export JAIL_ROOT="/opt/redquanta/vol"' >> ~/.bashrc
    source ~/.bashrc
    ```

---

## 🛠️ Distribution-Specific Instructions

### 🎯 Ubuntu/Debian (APT-based)

??? example "📦 Ubuntu Optimized Installation"

    #### Prerequisites Installation
    
    ```bash title="Install Required Packages"
    # Update package lists
    sudo apt update
    
    # Install required packages
    sudo apt install -y \
        curl wget git \
        build-essential \
        python3 python3-pip \
        golang-go \
        docker.io docker-compose \
        nmap masscan \
        nikto \
        john \
        hydra
    
    # Install snap packages
    sudo snap install code --classic
    sudo snap install postman
    
    # Install Go-based tools
    go install github.com/ffuf/ffuf@latest
    go install github.com/OJ/gobuster/v3@latest
    
    # Add Go bin to PATH
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    source ~/.bashrc
    ```
    
    #### SQLMap Installation
    
    ```bash title="Install SQLMap"
    # Clone SQLMap
    sudo git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
    
    # Create symlink
    sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
    
    # Make executable
    sudo chmod +x /opt/sqlmap/sqlmap.py
    ```
    
    #### Service Configuration
    
    ```bash title="Configure Docker"
    # Enable Docker service
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    
    # Logout and login again for group changes to take effect
    ```

### 🔴 RHEL/CentOS/Fedora (RPM-based)

??? example "📦 RHEL/CentOS Installation"

    #### Enable EPEL Repository
    
    ```bash title="Setup Repositories"
    # RHEL/CentOS 8+
    sudo dnf install -y epel-release
    
    # CentOS 7 (legacy)
    sudo yum install -y epel-release
    
    # Update package lists
    sudo dnf update -y
    ```
    
    #### Install Development Tools
    
    ```bash title="Development Environment"
    # Install development group
    sudo dnf groupinstall -y "Development Tools"
    
    # Install additional packages
    sudo dnf install -y \
        curl wget git \
        python3 python3-pip \
        golang \
        docker docker-compose \
        nmap \
        nikto \
        john \
        hydra-gtk
    
    # Install Node.js
    curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
    sudo dnf install -y nodejs
    ```
    
    #### Firewall Configuration
    
    ```bash title="Configure Firewall"
    # Configure firewall for development
    sudo firewall-cmd --zone=public --add-port=5891/tcp --permanent
    sudo firewall-cmd --reload
    
    # Or disable firewall for development (not recommended for production)
    sudo systemctl stop firewalld
    sudo systemctl disable firewalld
    ```

### 🏹 Arch Linux (Pacman)

??? example "📦 Arch Linux Installation"

    #### Install Base Packages
    
    ```bash title="Arch Package Installation"
    # Update system
    sudo pacman -Syu
    
    # Install base packages
    sudo pacman -S --needed \
        base-devel \
        git curl wget \
        nodejs npm \
        python python-pip \
        go \
        docker docker-compose \
        nmap masscan \
        nikto \
        john \
        hydra
    
    # Install pnpm
    npm install -g pnpm
    ```
    
    #### AUR Helper (yay)
    
    ```bash title="Install AUR Helper"
    # Install yay AUR helper
    git clone https://aur.archlinux.org/yay.git
    cd yay
    makepkg -si
    cd .. && rm -rf yay
    
    # Install AUR packages
    yay -S --needed \
        ffuf-bin \
        gobuster-bin \
        sqlmap
    ```
    
    #### Enable Services
    
    ```bash title="Service Configuration"
    # Enable and start Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    ```

### 🎯 Kali Linux (Security-Optimized)

!!! success "Recommended for Security Professionals"
    Kali Linux comes with most security tools pre-installed and optimized.

??? example "🔒 Kali Linux Optimized Setup"

    #### Advantages in Kali
    
    - ✅ Most security tools pre-installed
    - ✅ Optimized for penetration testing
    - ✅ Regular security updates
    - ✅ Community-maintained tool packages
    
    #### Quick Setup
    
    ```bash title="Kali Installation"
    # Update Kali repositories
    sudo apt update && sudo apt upgrade -y
    
    # Install Node.js and pnpm
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
    npm install -g pnpm
    
    # Clone and build RedQuanta MCP
    git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
    cd RedQuanta-MCP
    pnpm install && pnpm build
    
    # Setup jail root
    sudo mkdir -p /opt/redquanta/vol
    sudo chown $USER:$USER /opt/redquanta/vol
    ```
    
    #### Kali-Specific Optimizations
    
    ```bash title="Additional Tools"
    # Install additional tools not in default Kali
    sudo apt install -y \
        subfinder \
        amass \
        httpx \
        nuclei \
        gf
    
    # Configure metasploit database
    sudo msfdb init
    
    # Setup custom wordlists
    sudo mkdir -p /opt/redquanta/vol/wordlists
    sudo cp -r /usr/share/wordlists/* /opt/redquanta/vol/wordlists/
    sudo chown -R $USER:$USER /opt/redquanta/vol/wordlists
    ```

---

## 🐳 Docker Installation

!!! info "Docker Deployment"
    Perfect for isolated testing environments and production deployments.

### 📦 Using Official Docker Images

=== "Quick Setup"

    ```bash title="Simple Docker Run"
    # Pull the official image
    docker pull sc4rfurry/redquanta-mcp:latest
    
    # Run with basic configuration
    docker run -d \
      --name redquanta-mcp \
      -p 5891:5891 \
      -v $(pwd)/vol:/opt/redquanta/vol \
      -e NODE_ENV=production \
      sc4rfurry/redquanta-mcp:latest
    ```

=== "Docker Compose"

    ```yaml title="docker-compose.yml"
    version: '3.8'
    
    services:
      redquanta-mcp:
        image: sc4rfurry/redquanta-mcp:latest
        container_name: redquanta-mcp
        ports:
          - "5891:5891"
        volumes:
          - ./vol:/opt/redquanta/vol
          - ./config:/app/config
        environment:
          - NODE_ENV=production
          - JAIL_ROOT=/opt/redquanta/vol
          - LOG_LEVEL=info
        restart: unless-stopped
        
      # Optional: Add vulnerable targets for testing
      dvwa:
        image: vulnerables/web-dvwa
        container_name: dvwa-target
        ports:
          - "8080:80"
        networks:
          - redquanta-net
          
    networks:
      redquanta-net:
        driver: bridge
    ```

=== "Advanced Setup"

    ```bash title="Production Docker Setup"
    # Create Docker network for isolated testing
    docker network create redquanta-net
    
    # Run with network isolation
    docker run -d \
      --name redquanta-mcp \
      --network redquanta-net \
      -p 5891:5891 \
      -v $(pwd)/vol:/opt/redquanta/vol \
      -v $(pwd)/config:/app/config \
      -e NODE_ENV=production \
      -e DANGEROUS_MODE=false \
      --restart unless-stopped \
      sc4rfurry/redquanta-mcp:latest
    ```

---

## ⚙️ Advanced Configuration

### 🔧 System Optimization

!!! warning "Performance Tuning"
    These optimizations are recommended for high-load scanning environments.

=== "File Descriptors"

    ```bash title="Increase File Descriptor Limits"
    # Increase file descriptor limits for concurrent scanning
    echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf
    echo '* hard nofile 65536' | sudo tee -a /etc/security/limits.conf
    
    # For systemd services
    sudo mkdir -p /etc/systemd/system/redquanta-mcp.service.d/
    cat << EOF | sudo tee /etc/systemd/system/redquanta-mcp.service.d/limits.conf
    [Service]
    LimitNOFILE=65536
    EOF
    ```

=== "Network Optimization"

    ```bash title="Network Buffer Configuration"
    # Increase network buffer sizes
    echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
    echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
    echo 'net.ipv4.tcp_rmem = 4096 65536 134217728' | sudo tee -a /etc/sysctl.conf
    echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' | sudo tee -a /etc/sysctl.conf
    
    # Apply changes
    sudo sysctl -p
    ```

=== "Memory Management"

    ```bash title="Swap Configuration"
    # Configure swap for large scans
    sudo fallocate -l 4G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    
    # Make permanent
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    ```

### 🛡️ Security Hardening

!!! danger "Production Security"
    Essential security configurations for production environments.

=== "Dedicated User"

    ```bash title="Create System User"
    # Create redquanta user
    sudo useradd -r -s /bin/false -d /opt/redquanta redquanta
    
    # Setup directories with proper permissions
    sudo mkdir -p /opt/redquanta/{bin,vol,logs,config}
    sudo chown -R redquanta:redquanta /opt/redquanta
    sudo chmod 750 /opt/redquanta/vol
    ```

=== "Systemd Service"

    ```bash title="Production Service"
    # Create systemd service file
    sudo tee /etc/systemd/system/redquanta-mcp.service << EOF
    [Unit]
    Description=RedQuanta MCP Server
    After=network.target
    
    [Service]
    Type=simple
    User=redquanta
    Group=redquanta
    WorkingDirectory=/opt/redquanta
    ExecStart=/usr/bin/node /opt/redquanta/dist/server.js
    Restart=always
    RestartSec=10
    Environment=NODE_ENV=production
    Environment=JAIL_ROOT=/opt/redquanta/vol
    Environment=LOG_LEVEL=info
    
    # Security settings
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    ReadWritePaths=/opt/redquanta/vol /opt/redquanta/logs
    PrivateTmp=yes
    ProtectKernelTunables=yes
    ProtectControlGroups=yes
    RestrictRealtime=yes
    
    [Install]
    WantedBy=multi-user.target
    EOF
    
    # Enable and start service
    sudo systemctl daemon-reload
    sudo systemctl enable redquanta-mcp
    sudo systemctl start redquanta-mcp
    ```

### 📊 Monitoring & Logging

=== "Log Configuration"

    ```bash title="Setup Logging"
    # Create log directories
    sudo mkdir -p /var/log/redquanta
    sudo chown redquanta:redquanta /var/log/redquanta
    
    # Configure logrotate
    sudo tee /etc/logrotate.d/redquanta << EOF
    /var/log/redquanta/*.log {
        daily
        missingok
        rotate 30
        compress
        notifempty
        create 0644 redquanta redquanta
        postrotate
            systemctl reload redquanta-mcp
        endscript
    }
    EOF
    ```

=== "Health Monitoring"

    ```bash title="Health Check Script"
    # Create health check script
    sudo tee /opt/redquanta/bin/health-check.sh << 'EOF'
    #!/bin/bash
    
    # Check if service is running
    if ! systemctl is-active --quiet redquanta-mcp; then
        echo "RedQuanta MCP service is not running"
        exit 1
    fi
    
    # Check if port is listening
    if ! netstat -ln | grep -q ":5891 "; then
        echo "RedQuanta MCP is not listening on port 5891"
        exit 1
    fi
    
    echo "RedQuanta MCP is healthy"
    exit 0
    EOF
    
    sudo chmod +x /opt/redquanta/bin/health-check.sh
    ```

---

## 🧪 Testing Your Installation

### ✅ Verification Steps

!!! success "Installation Verification"
    Run these commands to verify your installation is working correctly.

```bash title="Verification Commands"
# Check Node.js and pnpm versions
node --version && npm --version && pnpm --version

# Verify RedQuanta build
ls -la /path/to/RedQuanta-MCP/dist/

# Test jail root permissions
ls -la /opt/redquanta/vol/

# Check installed security tools
which nmap && which masscan && which nikto && which hydra

# Test Docker (if installed)
docker --version && docker-compose --version
```

### 🚨 Common Issues & Solutions

??? bug "Node.js Version Issues"
    **Problem**: Wrong Node.js version installed
    
    **Solution**:
    ```bash
    # Remove old Node.js
    sudo apt remove nodejs npm
    
    # Install Node.js 20 LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
    ```

??? bug "Permission Denied Errors"
    **Problem**: Permission issues with jail root directory
    
    **Solution**:
    ```bash
    # Fix permissions
    sudo chown -R $USER:$USER /opt/redquanta/vol
    sudo chmod -R 755 /opt/redquanta/vol
    ```

??? bug "Docker Group Issues"
    **Problem**: Docker permission denied
    
    **Solution**:
    ```bash
    # Add user to docker group and restart session
    sudo usermod -aG docker $USER
    newgrp docker  # Or logout and login again
    ```

---

## 🔄 Updates & Maintenance

### 📦 Keeping RedQuanta Updated

```bash title="Update Commands"
# Update RedQuanta MCP
cd /path/to/RedQuanta-MCP
git pull origin main
pnpm install
pnpm build

# Update system packages (Ubuntu/Debian)
sudo apt update && sudo apt upgrade -y

# Update security tools
sudo apt install --only-upgrade nmap masscan nikto hydra
```

### 🧹 Maintenance Tasks

=== "Daily Tasks"

    ```bash title="Daily Maintenance"
    # Clean old logs
    find /var/log/redquanta -name "*.log" -mtime +7 -delete
    
    # Clean temporary files
    find /opt/redquanta/vol/tmp -type f -mtime +1 -delete
    
    # Check disk space
    df -h /opt/redquanta/vol
    ```

=== "Weekly Tasks"

    ```bash title="Weekly Maintenance"
    # Update wordlists
    cd /opt/redquanta/vol/wordlists
    wget -N https://github.com/danielmiessler/SecLists/archive/master.zip
    
    # Backup configuration
    tar -czf /backup/redquanta-config-$(date +%Y%m%d).tar.gz /opt/redquanta/config
    
    # Update security tools
    sudo apt update && sudo apt upgrade -y
    ```

---

## 📞 Support & Resources

### 🆘 Getting Help

!!! info "Support Channels"
    - 📖 **Documentation**: [https://redquanta-mcp.readthedocs.io](https://redquanta-mcp.readthedocs.io)
    - 🐛 **Issues**: [GitHub Issues](https://github.com/sc4rfurry/RedQuanta-MCP/issues)
    - 💬 **Discussions**: [GitHub Discussions](https://github.com/sc4rfurry/RedQuanta-MCP/discussions)
    - 📧 **Contact**: [redquanta@security.org](mailto:redquanta@security.org)

### 📚 Additional Resources

- 🔧 **Configuration Guide**: [Getting Started → Configuration](../getting-started/configuration.md)
- 🛡️ **Security Best Practices**: [Security → Security Model](../security/model.md)
- 🚀 **Performance Tuning**: [Development → Performance](../development/performance.md)
- 🐳 **Docker Deployment**: [Deployment → Docker](../deployment/docker.md)

---

<div align="center">

### 🎉 **Installation Complete!**

Your RedQuanta MCP Linux installation is now ready for professional penetration testing.

<p align="center">
  <a href="../getting-started/first-scan.md">
    <img src="https://img.shields.io/badge/Get%20Started-→-brightgreen?style=for-the-badge" alt="Get Started">
  </a>
</p>

</div> 