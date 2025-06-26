@echo off
set JAIL_ROOT=%USERPROFILE%\AppData\Local\RedQuanta\vol
set DANGEROUS_MODE=false
set MCP_MODE=rest
node dist/cli.js %*
