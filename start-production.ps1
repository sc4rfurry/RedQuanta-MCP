# RedQuanta MCP - Production Startup Script
# Optimized for enterprise deployment

param(
    [string]$Mode = "rest",
    [string]$Port = "5891",
    [string]$ServerHost = "0.0.0.0",
    [switch]$DangerousMode = $false,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
🛡️ RedQuanta MCP Production Startup Script

USAGE:
    .\start-production.ps1 [OPTIONS]

OPTIONS:
    -Mode <string>         Server mode: 'rest', 'stdio', or 'hybrid' (default: rest)
    -Port <string>         Server port (default: 5891)
    -ServerHost <string>   Server host (default: 0.0.0.0)
    -DangerousMode         Enable dangerous operations (requires explicit flag)
    -Help                  Show this help message

EXAMPLES:
    .\start-production.ps1                    # Start with default settings
    .\start-production.ps1 -Mode rest -Port 8080
    .\start-production.ps1 -DangerousMode    # Enable dangerous operations

PRODUCTION ENVIRONMENT:
    LOG_LEVEL=warn
    CACHE_ENABLED=true
    WEB_SEARCH_ENABLED=true
    NODE_ENV=production
"@ -ForegroundColor Cyan
    exit 0
}

# Production Configuration
Write-Host "🚀 RedQuanta MCP - Production Startup" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Gray

# Environment validation
if (-not (Test-Path "dist\server.js")) {
    Write-Host "❌ Production build not found. Building now..." -ForegroundColor Red
    Write-Host "🔧 Running production build..." -ForegroundColor Yellow
    npm run build:prod
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Build failed. Please check for errors." -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Production build completed" -ForegroundColor Green
}

# Stop existing processes
Write-Host "🔄 Stopping existing Node.js processes..." -ForegroundColor Yellow
try {
    Stop-Process -Name "node" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "✅ Previous processes stopped" -ForegroundColor Green
} catch {
    Write-Host "ℹ️  No existing processes found" -ForegroundColor Cyan
}

# Set production environment variables
$env:NODE_ENV = "production"
$env:LOG_LEVEL = "warn"
$env:MCP_MODE = $Mode
$env:PORT = $Port
$env:HOST = $ServerHost
$env:WEB_SEARCH_ENABLED = "true"
$env:CACHE_ENABLED = "true"
$env:CACHE_TTL = "1800"  # 30 minutes
$env:DANGEROUS_MODE = if ($DangerousMode) { "true" } else { "false" }

# Security jail root (Windows-compatible)
$jailRoot = "$env:USERPROFILE\RedQuanta\vol"
if (-not (Test-Path $jailRoot)) {
    New-Item -ItemType Directory -Path $jailRoot -Force | Out-Null
}
$env:JAIL_ROOT = $jailRoot

Write-Host "⚙️ Production Configuration:" -ForegroundColor Cyan
Write-Host "   Environment: $env:NODE_ENV" -ForegroundColor White
Write-Host "   Log Level: $env:LOG_LEVEL" -ForegroundColor White
Write-Host "   Server Mode: $env:MCP_MODE" -ForegroundColor White
Write-Host "   Host: $env:HOST" -ForegroundColor White
Write-Host "   Port: $env:PORT" -ForegroundColor White
Write-Host "   Web Search: $env:WEB_SEARCH_ENABLED" -ForegroundColor White
Write-Host "   Cache: $env:CACHE_ENABLED" -ForegroundColor White
Write-Host "   Dangerous Mode: $env:DANGEROUS_MODE" -ForegroundColor White
Write-Host "   Jail Root: $env:JAIL_ROOT" -ForegroundColor White

Write-Host ""
Write-Host "🎯 Starting RedQuanta MCP Production Server..." -ForegroundColor Green
Write-Host "ℹ️  Server will be available at: http://$env:HOST`:$env:PORT" -ForegroundColor Cyan
Write-Host "ℹ️  API Documentation: http://$env:HOST`:$env:PORT/docs" -ForegroundColor Cyan
Write-Host "ℹ️  Health Check: http://$env:HOST`:$env:PORT/health" -ForegroundColor Cyan
Write-Host ""

if ($DangerousMode) {
    Write-Host "⚠️  WARNING: Dangerous mode is ENABLED!" -ForegroundColor Red
    Write-Host "   This allows destructive operations. Use only in authorized environments." -ForegroundColor Red
    Write-Host ""
}

Write-Host "🛑 Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host "=" * 60 -ForegroundColor Gray
Write-Host ""

try {
    # Start the production server
    node dist/server.js
} catch {
    Write-Host ""
    Write-Host "❌ Server failed to start: $_" -ForegroundColor Red
    exit 1
} finally {
    Write-Host ""
    Write-Host "🛑 RedQuanta MCP Server stopped" -ForegroundColor Yellow
    Write-Host "💡 Thank you for using RedQuanta MCP!" -ForegroundColor Green
} 