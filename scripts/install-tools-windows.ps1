# RedQuanta MCP - Windows Tool Installation Script
# Installs pentesting tools on Windows using various package managers

param(
    [string[]]$Tools = @("all"),
    [switch]$UseChocolatey,
    [switch]$SkipDocker,
    [switch]$Verbose
)

Write-Host "🛠️ RedQuanta MCP - Windows Tool Installer" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Available tools configuration
$ToolsConfig = @{
    "nmap" = @{
        Name = "Nmap"
        Winget = "Nmap.Nmap"
        Chocolatey = "nmap"
        Verify = "nmap --version"
        Description = "Network discovery and security scanning"
    }
    "masscan" = @{
        Name = "Masscan"
        Winget = $null
        Chocolatey = "masscan"
        Manual = "https://github.com/robertdavidgraham/masscan/releases"
        Verify = "masscan --version"
        Description = "High-speed port scanner"
    }
    "ffuf" = @{
        Name = "FFUF"
        Go = "github.com/ffuf/ffuf@latest"
        Manual = "https://github.com/ffuf/ffuf/releases"
        Verify = "ffuf -V"
        Description = "Fast web fuzzer"
    }
    "gobuster" = @{
        Name = "Gobuster"
        Go = "github.com/OJ/gobuster/v3@latest"
        Manual = "https://github.com/OJ/gobuster/releases"
        Verify = "gobuster version"
        Description = "Directory and DNS enumeration"
    }
    "nikto" = @{
        Name = "Nikto"
        Manual = "https://github.com/sullo/nikto"
        Verify = "perl nikto.pl -Version"
        Description = "Web vulnerability scanner"
        Requirements = @("Perl")
    }
    "john" = @{
        Name = "John the Ripper"
        Winget = $null
        Chocolatey = "john-the-ripper"
        Manual = "https://www.openwall.com/john/"
        Verify = "john --version"
        Description = "Password cracking tool"
    }
    "hydra" = @{
        Name = "Hydra"
        Winget = $null
        Chocolatey = "hydra"
        Manual = "https://github.com/vanhauser-thc/thc-hydra"
        Verify = "hydra -h"
        Description = "Network logon cracker"
    }
    "python" = @{
        Name = "Python 3"
        Winget = "Python.Python.3.11"
        Chocolatey = "python"
        Verify = "python --version"
        Description = "Required for SQLMap and other tools"
    }
    "git" = @{
        Name = "Git"
        Winget = "Git.Git"
        Chocolatey = "git"
        Verify = "git --version"
        Description = "Version control (required for manual installs)"
    }
    "go" = @{
        Name = "Go"
        Winget = "GoLang.Go"
        Chocolatey = "golang"
        Verify = "go version"
        Description = "Required for Go-based tools"
    }
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PackageManager {
    param([string]$Manager)
    
    try {
        switch ($Manager) {
            "winget" { winget --version | Out-Null; return $true }
            "chocolatey" { choco --version | Out-Null; return $true }
            "go" { go version | Out-Null; return $true }
            default { return $false }
        }
    } catch {
        return $false
    }
}

function Install-Tool {
    param(
        [string]$ToolKey,
        [hashtable]$Config
    )
    
    Write-Host "📦 Installing $($Config.Name)..." -ForegroundColor Blue
    
    # Check if already installed
    if ($Config.Verify) {
        try {
            Invoke-Expression $Config.Verify | Out-Null
            Write-Host "✅ $($Config.Name) is already installed" -ForegroundColor Green
            return $true
        } catch {
            # Not installed, continue
        }
    }
    
    $installed = $false
    
    # Try Winget first
    if (!$UseChocolatey -and $Config.Winget -and (Test-PackageManager "winget")) {
        try {
            Write-Host "  🎯 Installing via Winget..." -ForegroundColor Yellow
            winget install $Config.Winget --accept-source-agreements --accept-package-agreements
            $installed = $true
        } catch {
            Write-Warning "Winget installation failed: $_"
        }
    }
    
    # Try Chocolatey
    if (!$installed -and $Config.Chocolatey -and (Test-PackageManager "chocolatey")) {
        try {
            Write-Host "  🍫 Installing via Chocolatey..." -ForegroundColor Yellow
            choco install $Config.Chocolatey -y
            $installed = $true
        } catch {
            Write-Warning "Chocolatey installation failed: $_"
        }
    }
    
    # Try Go install
    if (!$installed -and $Config.Go -and (Test-PackageManager "go")) {
        try {
            Write-Host "  🐹 Installing via Go..." -ForegroundColor Yellow
            go install $Config.Go
            $installed = $true
        } catch {
            Write-Warning "Go installation failed: $_"
        }
    }
    
    # Manual installation guidance
    if (!$installed -and $Config.Manual) {
        Write-Host "  📋 Manual installation required:" -ForegroundColor Yellow
        Write-Host "     Download from: $($Config.Manual)" -ForegroundColor White
        if ($Config.Requirements) {
            Write-Host "     Requirements: $($Config.Requirements -join ', ')" -ForegroundColor White
        }
    }
    
    # Verify installation
    if ($Config.Verify) {
        try {
            Invoke-Expression $Config.Verify | Out-Null
            Write-Host "✅ $($Config.Name) installed successfully" -ForegroundColor Green
            return $true
        } catch {
            Write-Warning "$($Config.Name) installation could not be verified"
            return $false
        }
    }
    
    return $installed
}

# Check prerequisites
Write-Host "🔍 Checking prerequisites..." -ForegroundColor Blue

$isAdmin = Test-AdminPrivileges
if ($isAdmin) {
    Write-Host "✅ Running with administrator privileges" -ForegroundColor Green
} else {
    Write-Warning "Not running as administrator. Some installations may fail."
    Write-Host "💡 Consider running: Start-Process PowerShell -Verb RunAs" -ForegroundColor Yellow
}

# Check package managers
Write-Host "📦 Checking package managers..." -ForegroundColor Blue

$wingetAvailable = Test-PackageManager "winget"
$chocoAvailable = Test-PackageManager "chocolatey"
$goAvailable = Test-PackageManager "go"

Write-Host "  Winget: $(if($wingetAvailable){'✅'}else{'❌'})" -ForegroundColor $(if($wingetAvailable){'Green'}else{'Red'})
Write-Host "  Chocolatey: $(if($chocoAvailable){'✅'}else{'❌'})" -ForegroundColor $(if($chocoAvailable){'Green'}else{'Red'})
Write-Host "  Go: $(if($goAvailable){'✅'}else{'❌'})" -ForegroundColor $(if($goAvailable){'Green'}else{'Red'})

# Install Chocolatey if needed and requested
if (!$chocoAvailable -and ($UseChocolatey -or !$wingetAvailable)) {
    Write-Host "🍫 Installing Chocolatey..." -ForegroundColor Blue
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        $chocoAvailable = $true
        Write-Host "✅ Chocolatey installed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to install Chocolatey: $_"
    }
}

# Determine which tools to install
$toolsToInstall = if ($Tools -contains "all") {
    $ToolsConfig.Keys
} else {
    $Tools
}

Write-Host ""
Write-Host "🚀 Installing tools: $($toolsToInstall -join ', ')" -ForegroundColor Cyan
Write-Host ""

# Install core dependencies first
$coreTools = @("git", "python", "go")
foreach ($tool in $coreTools) {
    if ($toolsToInstall -contains $tool -or $Tools -contains "all") {
        Install-Tool $tool $ToolsConfig[$tool]
        Write-Host ""
    }
}

# Install pentesting tools
$pentestTools = $toolsToInstall | Where-Object { $_ -notin $coreTools }
foreach ($tool in $pentestTools) {
    if ($ToolsConfig.ContainsKey($tool)) {
        Install-Tool $tool $ToolsConfig[$tool]
        Write-Host ""
    } else {
        Write-Warning "Unknown tool: $tool"
    }
}

# Install Docker fallback tools
if (!$SkipDocker) {
    Write-Host "🐳 Setting up Docker fallback images..." -ForegroundColor Blue
    
    $dockerImages = @(
        "instrumentisto/nmap:latest",
        "ivre/masscan:latest",
        "ghcr.io/ffuf/ffuf:latest",
        "secfigo/nikto:latest",
        "paoloo/sqlmap:latest"
    )
    
    try {
        docker --version | Out-Null
        foreach ($image in $dockerImages) {
            Write-Host "  📥 Pulling $image..." -ForegroundColor Yellow
            docker pull $image
        }
        Write-Host "✅ Docker fallback images ready" -ForegroundColor Green
    } catch {
        Write-Warning "Docker not available for fallback images"
    }
}

# Manual installation instructions
Write-Host ""
Write-Host "📋 Manual Installation Notes:" -ForegroundColor Cyan
Write-Host ""

Write-Host "SQLMap:" -ForegroundColor Yellow
Write-Host "  git clone https://github.com/sqlmapproject/sqlmap.git" -ForegroundColor White
Write-Host "  Add to PATH or use: python sqlmap\sqlmap.py" -ForegroundColor White
Write-Host ""

Write-Host "Nikto:" -ForegroundColor Yellow
Write-Host "  git clone https://github.com/sullo/nikto.git" -ForegroundColor White
Write-Host "  Requires Perl: winget install StrawberryPerl.StrawberryPerl" -ForegroundColor White
Write-Host ""

Write-Host "Metasploit:" -ForegroundColor Yellow
Write-Host "  Download installer from: https://www.metasploit.com/" -ForegroundColor White
Write-Host "  Or use Docker: docker run -it metasploitframework/metasploit-framework" -ForegroundColor White
Write-Host ""

Write-Host "🎉 Tool installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "💡 Tips:" -ForegroundColor Cyan
Write-Host "- Restart your terminal to refresh PATH" -ForegroundColor White
Write-Host "- Run 'redquanta-cli.bat doctor' to verify installations" -ForegroundColor White
Write-Host "- Use Docker fallbacks for missing tools" -ForegroundColor White 