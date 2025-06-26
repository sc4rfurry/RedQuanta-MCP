@echo off
REM RedQuanta MCP Server - Windows Startup Script
echo 🚀 Starting RedQuanta MCP Server on Windows...

REM Kill any existing node processes
taskkill /F /IM node.exe 2>nul

REM Wait a moment for processes to terminate
timeout /t 2 /nobreak >nul

REM Set environment variables for Windows
set WEB_SEARCH_ENABLED=true
set MCP_MODE=rest
set PORT=5891
set HOST=0.0.0.0
set CACHE_ENABLED=true
set LOG_LEVEL=info

REM Check if dist folder exists
if not exist "dist" (
    echo ❌ dist folder not found. Running build first...
    call npm run build
    if errorlevel 1 (
        echo ❌ Build failed. Please check for errors.
        pause
        exit /b 1
    )
)

REM Start the server
echo ✅ Starting RedQuanta MCP Server...
echo ℹ️  Server will be available at: http://localhost:5891
echo ℹ️  API Documentation: http://localhost:5891/docs
echo ℹ️  Health Check: http://localhost:5891/health
echo.
echo 🛑 Press Ctrl+C to stop the server
echo.

node dist/server.js

echo.
echo 🛑 Server stopped
pause
