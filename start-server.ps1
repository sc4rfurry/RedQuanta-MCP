# RedQuanta MCP Server - PowerShell Startup Script
Write-Host "🚀 Starting RedQuanta MCP Server on Windows..." -ForegroundColor Green

# Stop any existing node processes
Write-Host "🔄 Stopping any existing Node.js processes..." -ForegroundColor Yellow
try {
    Stop-Process -Name "node" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "✅ Existing processes stopped" -ForegroundColor Green
} catch {
    Write-Host "ℹ️  No existing Node.js processes found" -ForegroundColor Cyan
}

# Set environment variables
$env:WEB_SEARCH_ENABLED = "true"
$env:MCP_MODE = "rest"
$env:PORT = "5891"
$env:HOST = "0.0.0.0"
$env:CACHE_ENABLED = "true"
$env:LOG_LEVEL = "info"
$env:DANGEROUS_MODE = "false"

Write-Host "📋 Environment Configuration:" -ForegroundColor Cyan
Write-Host "   WEB_SEARCH_ENABLED: $env:WEB_SEARCH_ENABLED" -ForegroundColor White
Write-Host "   MCP_MODE: $env:MCP_MODE" -ForegroundColor White
Write-Host "   PORT: $env:PORT" -ForegroundColor White
Write-Host "   HOST: $env:HOST" -ForegroundColor White
Write-Host "   CACHE_ENABLED: $env:CACHE_ENABLED" -ForegroundColor White
Write-Host "   LOG_LEVEL: $env:LOG_LEVEL" -ForegroundColor White

# Check if dist folder exists
if (-not (Test-Path "dist")) {
    Write-Host "❌ dist folder not found. Running build first..." -ForegroundColor Red
    Write-Host "🔧 Building project..." -ForegroundColor Yellow
    npm run build
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Build failed. Please check for errors." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "✅ Build completed successfully" -ForegroundColor Green
}

# Start the server
Write-Host ""
Write-Host "🎯 Starting RedQuanta MCP Server..." -ForegroundColor Green
Write-Host "ℹ️  Server will be available at: http://localhost:$env:PORT" -ForegroundColor Cyan
Write-Host "ℹ️  API Documentation: http://localhost:$env:PORT/docs" -ForegroundColor Cyan
Write-Host "ℹ️  ReDoc Documentation: http://localhost:$env:PORT/redoc" -ForegroundColor Cyan
Write-Host "ℹ️  Health Check: http://localhost:$env:PORT/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "🛑 Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host "=" * 50 -ForegroundColor DarkGray
Write-Host ""

try {
    # Start the server
    node dist/server.js
} catch {
    Write-Host ""
    Write-Host "❌ Server failed to start: $_" -ForegroundColor Red
} finally {
    Write-Host ""
    Write-Host "🛑 Server stopped" -ForegroundColor Yellow
    Write-Host "Press Enter to exit..." -ForegroundColor Gray
    Read-Host
} 