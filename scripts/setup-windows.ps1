# RedQuanta MCP - Windows Setup Script
# Initializes the RedQuanta MCP environment on Windows with proper encoding

param(
    [string]$JailRoot = "",
    [switch]$InstallTools = $false,
    [switch]$Force = $false
)

# Set console encoding to UTF-8 to avoid character issues
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "RedQuanta MCP - Windows Setup" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Function to test directory creation permissions
function Test-DirectoryPermissions {
    param([string]$Path)
    
    try {
        $testDir = Join-Path $Path "test-permissions"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        Remove-Item -Path $testDir -Force | Out-Null
        return $true
    } catch {
        return $false
    }
}

# Function to get safe jail root path
function Get-SafeJailRoot {
    if ($JailRoot -and (Test-Path $JailRoot -IsValid)) {
        Write-Host "Using custom jail root: $JailRoot" -ForegroundColor Blue
        return $JailRoot
    }

    # Try paths in order of preference (most secure to least secure)
    $candidatePaths = @(
        # Most preferred: LocalAppData (guaranteed writable)
        (Join-Path $env:LOCALAPPDATA "RedQuanta\vol"),
        # Alternative: User Documents
        (Join-Path $env:USERPROFILE "Documents\RedQuanta\vol"),
        # Alternative: User profile root
        (Join-Path $env:USERPROFILE "RedQuanta\vol"),
        # Last resort: Temp directory (not persistent)
        (Join-Path $env:TEMP "RedQuanta\vol")
    )

    foreach ($path in $candidatePaths) {
        $parentDir = Split-Path $path -Parent
        if (Test-DirectoryPermissions $parentDir) {
            Write-Host "Selected safe jail root: $path" -ForegroundColor Green
            return $path
        } else {
            Write-Host "Cannot write to: $parentDir" -ForegroundColor Yellow
        }
    }

    # Fallback to temp if nothing else works
    $fallback = Join-Path $env:TEMP "RedQuanta\vol"
    Write-Warning "Using fallback jail root (not persistent): $fallback"
    return $fallback
}

# Get safe jail root
$SafeJailRoot = Get-SafeJailRoot
Write-Host "Jail root will be: $SafeJailRoot" -ForegroundColor Blue

# Create jail root directory
Write-Host "Creating jail root directory..." -ForegroundColor Blue
try {
    if (-not (Test-Path $SafeJailRoot)) {
        New-Item -ItemType Directory -Path $SafeJailRoot -Force | Out-Null
        Write-Host "Created jail root: $SafeJailRoot" -ForegroundColor Green
    } else {
        Write-Host "Jail root already exists: $SafeJailRoot" -ForegroundColor Green
    }
    
    # Test write permissions
    $testFile = Join-Path $SafeJailRoot "test-write.txt"
    "test" | Out-File -FilePath $testFile -Encoding UTF8
    Remove-Item $testFile -Force
    Write-Host "Jail root is writable" -ForegroundColor Green
    
    # Create standard subdirectories
    $subdirs = @("tmp", "reports", "uploads", "downloads", "wordlists", "configs", "scripts", "results", "logs", "cache", "workspace")
    foreach ($subdir in $subdirs) {
        $dirPath = Join-Path $SafeJailRoot $subdir
        if (-not (Test-Path $dirPath)) {
            New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
        }
    }
    Write-Host "Created subdirectories" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to create or access jail root: $_"
    Write-Host "Try running as administrator or choose a different path" -ForegroundColor Yellow
    exit 1
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Blue
try {
    pnpm install
    Write-Host "Dependencies installed" -ForegroundColor Green
} catch {
    Write-Error "Failed to install dependencies: $_"
    exit 1
}

# Build project
Write-Host "Building project..." -ForegroundColor Blue
try {
    pnpm build
    Write-Host "Project built successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to build project: $_"
    exit 1
}

# Update configuration files with safe jail root
Write-Host "Updating configuration..." -ForegroundColor Blue

# Update allowedPaths.json
$allowedPathsPath = "config\allowedPaths.json"
if (Test-Path $allowedPathsPath) {
    try {
        $config = Get-Content $allowedPathsPath | ConvertFrom-Json
        $config.jailRoot = $SafeJailRoot
        $config | ConvertTo-Json -Depth 10 | Set-Content $allowedPathsPath -Encoding UTF8
        Write-Host "Updated allowedPaths.json with Windows jail root" -ForegroundColor Green
    } catch {
        Write-Warning "Could not update allowedPaths.json: $_"
    }
}

# Update Windows-specific config if it exists
$allowedPathsWindowsPath = "config\allowedPaths-windows.json"
if (Test-Path $allowedPathsWindowsPath) {
    try {
        $config = Get-Content $allowedPathsWindowsPath -Raw | ConvertFrom-Json
        $config.jailRoot = $SafeJailRoot
        $config | ConvertTo-Json -Depth 10 | Set-Content $allowedPathsWindowsPath -Encoding UTF8
        Write-Host "Updated allowedPaths-windows.json" -ForegroundColor Green
    } catch {
        Write-Warning "Could not update allowedPaths-windows.json: $_"
    }
}

# Set environment variables
Write-Host "Setting environment variables..." -ForegroundColor Blue
try {
    [Environment]::SetEnvironmentVariable("JAIL_ROOT", $SafeJailRoot, "User")
    [Environment]::SetEnvironmentVariable("MCP_MODE", "rest", "User")
    [Environment]::SetEnvironmentVariable("MCP_PORT", "5891", "User")
    Write-Host "Environment variables set" -ForegroundColor Green
} catch {
    Write-Warning "Could not set environment variables: $_"
}

# Install pentesting tools (optional)
if ($InstallTools) {
    Write-Host "Installing pentesting tools..." -ForegroundColor Blue
    
    # Check if winget is available
    $wingetAvailable = $false
    try {
        winget --version | Out-Null
        $wingetAvailable = $true
        Write-Host "Winget is available" -ForegroundColor Green
    } catch {
        Write-Warning "Winget is not available, skipping tool installation"
    }
    
    if ($wingetAvailable) {
        $tools = @(
            @{Name="Nmap"; Package="Insecure.Nmap"},
            @{Name="Git"; Package="Git.Git"},
            @{Name="Python"; Package="Python.Python.3.12"},
            @{Name="Go"; Package="GoLang.Go"}
        )
        
        foreach ($tool in $tools) {
            Write-Host "Installing $($tool.Name)..." -ForegroundColor Yellow
            try {
                winget install $tool.Package --accept-source-agreements --accept-package-agreements --silent
                Write-Host "Installed $($tool.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to install $($tool.Name): $_"
            }
        }
        
        # Install Go-based tools if Go is available
        try {
            go version | Out-Null
            Write-Host "Installing Go-based tools..." -ForegroundColor Yellow
            
            # FFUF
            go install github.com/ffuf/ffuf@latest
            Write-Host "Installed FFUF" -ForegroundColor Green
            
            # Gobuster
            go install github.com/OJ/gobuster/v3@latest
            Write-Host "Installed Gobuster" -ForegroundColor Green
            
        } catch {
            Write-Warning "Go not available, skipping Go-based tools"
        }
        
        # Install Python-based tools if Python is available
        try {
            python --version | Out-Null
            Write-Host "Installing Python-based tools..." -ForegroundColor Yellow
            
            # SQLMap
            $sqlmapDir = Join-Path $SafeJailRoot "tools\sqlmap"
            if (-not (Test-Path $sqlmapDir)) {
                git clone https://github.com/sqlmapproject/sqlmap.git $sqlmapDir
                Write-Host "Installed SQLMap" -ForegroundColor Green
            }
            
        } catch {
            Write-Warning "Python not available, skipping Python-based tools"
        }
    }
}

# Check Docker availability
Write-Host "Checking Docker availability..." -ForegroundColor Blue
try {
    docker --version | Out-Null
    Write-Host "Docker is available" -ForegroundColor Green
} catch {
    Write-Warning "Docker not found - some tools may fall back to local installation"
}

# Check for security tools
Write-Host "Checking for security tools..." -ForegroundColor Blue
$tools = @("nmap", "masscan", "ffuf", "gobuster", "nikto", "sqlmap")
$foundTools = @()
$missingTools = @()

foreach ($tool in $tools) {
    try {
        $cmd = if ($tool -eq "sqlmap") { "python" } else { $tool }
        $null = & $cmd --version 2>$null
        $foundTools += $tool
        Write-Host "  Found: $tool" -ForegroundColor Green
    } catch {
        $missingTools += $tool
        Write-Host "  Missing: $tool" -ForegroundColor Red
    }
}

if ($missingTools.Count -gt 0) {
    Write-Host ""
    Write-Host "Missing tools can be installed via:" -ForegroundColor Yellow
    Write-Host "   - Winget: winget install <tool>" -ForegroundColor Gray
    Write-Host "   - Chocolatey: choco install <tool>" -ForegroundColor Gray
    Write-Host "   - Docker: Will auto-fallback during execution" -ForegroundColor Gray
    Write-Host "   - Rerun with -InstallTools flag to auto-install" -ForegroundColor Gray
}

# Create startup script
Write-Host "Creating startup scripts..." -ForegroundColor Blue

$startScriptContent = @"
@echo off
echo Starting RedQuanta MCP Server...
cd /d "%~dp0"
set JAIL_ROOT=$SafeJailRoot
set MCP_MODE=rest
set MCP_PORT=5891
node dist/server.js %*
"@

try {
    $startScriptContent | Out-File -FilePath "start-windows.bat" -Encoding ASCII
    Write-Host "Created start-windows.bat" -ForegroundColor Green
} catch {
    Write-Warning "Could not create start-windows.bat: $_"
}

# CLI script
$cliScriptContent = @"
@echo off
cd /d "%~dp0"
set JAIL_ROOT=$SafeJailRoot
node dist/cli.js %*
"@

try {
    $cliScriptContent | Out-File -FilePath "redquanta-cli.bat" -Encoding ASCII
    Write-Host "Created redquanta-cli.bat" -ForegroundColor Green
} catch {
    Write-Warning "Could not create redquanta-cli.bat: $_"
}

Write-Host ""
Write-Host "RedQuanta MCP Windows Setup Complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""
Write-Host "Jail Root: $SafeJailRoot" -ForegroundColor Cyan
Write-Host "Found Tools: $($foundTools.Count)/$($tools.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor Yellow
Write-Host "  .\start-windows.bat          # Start MCP server" -ForegroundColor White
Write-Host "  .\redquanta-cli.bat tools    # List available tools" -ForegroundColor White
Write-Host "  .\redquanta-cli.bat doctor   # Check system health" -ForegroundColor White
Write-Host ""

if ($missingTools.Count -gt 0) {
    Write-Host "Some tools are missing. RedQuanta will attempt to use Docker fallbacks." -ForegroundColor Yellow
    Write-Host "For best performance, consider installing missing tools locally." -ForegroundColor Gray
    Write-Host "Rerun with -InstallTools to automatically install available tools." -ForegroundColor Gray
    Write-Host ""
} 