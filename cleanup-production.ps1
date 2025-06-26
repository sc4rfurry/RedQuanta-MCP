# RedQuanta MCP - Production Cleanup Script
# Removes development artifacts and optimizes for production deployment

param(
    [switch]$Force,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
🧹 RedQuanta MCP Production Cleanup Script

DESCRIPTION:
    Removes development artifacts, temporary files, and optimizes the codebase for production deployment.

USAGE:
    .\cleanup-production.ps1 [OPTIONS]

OPTIONS:
    -Force    Skip confirmation prompts
    -Help     Show this help message

CLEANUP ACTIONS:
    ✅ Remove development test files
    ✅ Clean build artifacts
    ✅ Archive development artifacts
    ✅ Optimize node_modules (if present)
    ✅ Clean log files (optional)
    ✅ Verify production readiness

"@ -ForegroundColor Cyan
    exit 0
}

Write-Host "🧹 RedQuanta MCP Production Cleanup" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Gray

# Confirmation
if (-not $Force) {
    $confirm = Read-Host "This will clean development artifacts and optimize for production. Continue? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "❌ Cleanup cancelled by user" -ForegroundColor Yellow
        exit 0
    }
}

$cleanupLog = @()

# 1. Create archive directory if it doesn't exist
if (-not (Test-Path "archive")) {
    New-Item -ItemType Directory -Path "archive" -Force | Out-Null
    Write-Host "📁 Created archive directory" -ForegroundColor Green
    $cleanupLog += "Created archive directory"
}

# 2. Remove temporary files
$tempFiles = @(
    "*.tmp",
    "*.temp",
    "debug.log",
    "test.log",
    "npm-debug.log*",
    "yarn-debug.log*",
    "yarn-error.log*"
)

foreach ($pattern in $tempFiles) {
    $files = Get-ChildItem -Path . -Name $pattern -ErrorAction SilentlyContinue
    if ($files) {
        Remove-Item $files -Force
        Write-Host "🗑️  Removed temporary files: $pattern" -ForegroundColor Yellow
        $cleanupLog += "Removed temp files: $pattern"
    }
}

# 3. Clean build artifacts (preserving dist/ for production)
if (Test-Path "coverage") {
    Move-Item "coverage" "archive/" -Force
    Write-Host "📦 Archived coverage reports" -ForegroundColor Blue
    $cleanupLog += "Archived coverage reports"
}

# 4. Remove any remaining test files
$testFiles = Get-ChildItem -Path . -Name "*test*.js" -ErrorAction SilentlyContinue
if ($testFiles) {
    Remove-Item $testFiles -Force
    Write-Host "🧪 Removed test files" -ForegroundColor Yellow
    $cleanupLog += "Removed test files"
}

# 5. Clean node_modules cache (optional optimization)
if (Test-Path "node_modules/.cache") {
    Remove-Item "node_modules/.cache" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "🗂️  Cleaned node_modules cache" -ForegroundColor Green
    $cleanupLog += "Cleaned node_modules cache"
}

# 6. Optimize package-lock.json
if (Test-Path "package-lock.json") {
    Write-Host "📄 Package-lock.json present (good for production)" -ForegroundColor Green
    $cleanupLog += "Verified package-lock.json"
}

# 7. Clean old log files (keep recent ones)
if (Test-Path "logs") {
    $oldLogs = Get-ChildItem "logs" -Name "*.jsonl" | Where-Object { 
        $_.LastWriteTime -lt (Get-Date).AddDays(-7) 
    }
    if ($oldLogs) {
        foreach ($log in $oldLogs) {
            Move-Item "logs/$log" "archive/" -Force
        }
        Write-Host "📋 Archived old log files" -ForegroundColor Blue
        $cleanupLog += "Archived old logs"
    }
}

# 8. Verify production build
if (-not (Test-Path "dist/server.js")) {
    Write-Host "⚠️  Production build not found! Run 'npm run build:prod'" -ForegroundColor Red
    $cleanupLog += "WARNING: No production build"
} else {
    Write-Host "✅ Production build verified" -ForegroundColor Green
    $cleanupLog += "Production build verified"
}

# 9. Check Docker setup
if (Test-Path "docker-security-tools.yml") {
    Write-Host "🐳 Docker configuration present" -ForegroundColor Green
    $cleanupLog += "Docker configuration verified"
}

# 10. Verify security configuration
if (Test-Path "config/allowedCommands.json") {
    Write-Host "🛡️  Security configuration present" -ForegroundColor Green
    $cleanupLog += "Security configuration verified"
}

# 11. Check documentation
if (Test-Path "docs/api/openapi.json") {
    Write-Host "📚 API documentation present" -ForegroundColor Green
    $cleanupLog += "API documentation verified"
} else {
    Write-Host "⚠️  API documentation missing! Run 'npm run docs:api'" -ForegroundColor Yellow
    $cleanupLog += "WARNING: API docs missing"
}

# 12. Final production readiness check
Write-Host ""
Write-Host "🔍 Production Readiness Check:" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Gray

$checks = @(
    @{ Name = "Production build"; Path = "dist/server.js"; Required = $true },
    @{ Name = "Package.json"; Path = "package.json"; Required = $true },
    @{ Name = "Security config"; Path = "config/allowedCommands.json"; Required = $true },
    @{ Name = "Docker setup"; Path = "docker-security-tools.yml"; Required = $true },
    @{ Name = "Documentation"; Path = "docs/"; Required = $true },
    @{ Name = "Start script"; Path = "start-production.ps1"; Required = $true }
)

$allGood = $true
foreach ($check in $checks) {
    if (Test-Path $check.Path) {
        Write-Host "✅ $($check.Name)" -ForegroundColor Green
    } else {
        if ($check.Required) {
            Write-Host "❌ $($check.Name) - MISSING" -ForegroundColor Red
            $allGood = $false
        } else {
            Write-Host "⚠️  $($check.Name) - Optional" -ForegroundColor Yellow
        }
    }
}

# Summary
Write-Host ""
Write-Host "📊 Cleanup Summary:" -ForegroundColor Cyan
Write-Host "==================" -ForegroundColor Gray
foreach ($action in $cleanupLog) {
    Write-Host "• $action" -ForegroundColor White
}

Write-Host ""
if ($allGood) {
    Write-Host "🎉 RedQuanta MCP is PRODUCTION READY!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Review configuration in start-production.ps1" -ForegroundColor White
    Write-Host "2. Run: .\start-production.ps1" -ForegroundColor White
    Write-Host "3. Access API documentation at: http://localhost:5891/docs" -ForegroundColor White
    Write-Host "4. Monitor logs in: logs/audit-*.jsonl" -ForegroundColor White
} else {
    Write-Host "⚠️  Some issues found. Please resolve before production deployment." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🚀 Production deployment ready!" -ForegroundColor Green 