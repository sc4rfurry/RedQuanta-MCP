# 🎯 Cursor AI Integration Guide for RedQuanta MCP

This guide will help you integrate RedQuanta MCP with Cursor AI for intelligent penetration testing workflows.

## 🚀 Quick Setup

### Step 1: Prepare RedQuanta MCP

```powershell
# Ensure the server is built and ready
pnpm build

# Create jail directory
mkdir -p vol

# Test basic functionality
node dist/server.js --mode=stdio
```

### Step 2: Configure Cursor AI

#### Option A: Manual Configuration (Recommended)

1. **Open Cursor AI Settings**
   - Press `Ctrl+,` (or `Cmd+,` on macOS)
   - Search for "MCP" or "Model Context Protocol"

2. **Add RedQuanta MCP Server**
   
   Add this configuration to your Cursor settings:

   ```json
   {
     "mcp": {
       "servers": {
         "redquanta": {
           "command": "node",
           "args": [
             "./dist/server.js",
             "--mode=stdio"
           ],
           "cwd": ".",
           "env": {
             "NODE_ENV": "development",
             "LOG_LEVEL": "info",
             "JAIL_ROOT": "./vol",
             "DANGEROUS_MODE": "false"
           }
         }
       }
     }
   }
   ```

   **⚠️ Important**: Replace `.` with your actual project path if needed.

#### Option B: Using Configuration File

1. **Copy Configuration**
   ```powershell
   # Copy the provided config file to Cursor's settings directory
   # Location varies by OS:
   # Windows: %APPDATA%\Cursor\User\
   # macOS: ~/Library/Application Support/Cursor/User/
   # Linux: ~/.config/Cursor/User/
   
   cp cursor-mcp-config.json "%APPDATA%\Cursor\User\cursor-mcp.json"
   ```

2. **Update Paths**
   Edit the copied file to match your system paths.

### Step 3: Restart Cursor AI

Close and restart Cursor AI completely to load the new MCP configuration.

### Step 4: Verify Integration

1. **Check MCP Status**
   - Look for MCP indicators in Cursor's status bar
   - You should see "RedQuanta MCP" listed as available

2. **Test Basic Functionality**
   - Open a new chat or file
   - Type: `@redquanta` or mention RedQuanta MCP
   - You should see tool suggestions

## 🎭 Usage Examples

### Example 1: Network Reconnaissance

```
You: @redquanta-mcp Please help me scan the network 192.168.1.0/24 for live hosts and services

Expected Response: Cursor AI will use our nmap_scan and workflow_enum tools to:
1. Discover live hosts
2. Scan for open ports
3. Identify running services
4. Provide security recommendations
```

### Example 2: Web Application Testing

```
You: @redquanta-mcp Analyze the security of https://example.com

Expected Response: Cursor AI will orchestrate:
1. Directory enumeration with FFUF
2. Vulnerability scanning with Nikto
3. SSL/TLS analysis (if plugin loaded)
4. Comprehensive security report
```

### Example 3: Help and Documentation

```
You: @redquanta-mcp What tools are available for web testing?

Expected Response: Cursor AI will use our help_system to provide:
1. List of web-focused tools
2. Usage examples and parameters
3. Best practices and safety guidelines
4. Workflow recommendations
```

## 🔧 Advanced Configuration

### Enabling Dangerous Operations

For advanced testing (password cracking, SQL injection):

```json
{
  "env": {
    "DANGEROUS_MODE": "true"
  }
}
```

**⚠️ Warning**: Only enable dangerous mode in authorized testing environments.

### Custom Jail Root

To change the filesystem jail location:

```json
{
  "env": {
    "JAIL_ROOT": "C:/PentestJail"
  }
}
```

### Logging Configuration

For detailed debugging:

```json
{
  "env": {
    "LOG_LEVEL": "debug"
  }
}
```

## 🧪 Manual Testing

### Test Server Connectivity

```powershell
# Start server in stdio mode
$env:JAIL_ROOT = ".\vol"
node dist/server.js --mode=stdio

# In another terminal, test MCP commands
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node dist/server.js --mode=stdio
```

### Test Tool Execution

```powershell
# Test help system
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"help_system","arguments":{"tool":"nmap_scan"}}}' | node dist/server.js --mode=stdio

# Test filesystem operations (safe)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem_ops","arguments":{"operation":"list","path":"."}}}' | node dist/server.js --mode=stdio
```

## 🎯 Available Tools for Cursor AI

RedQuanta MCP provides these tools for Cursor AI:

### 🌐 Network Tools
- **nmap_scan** - Network discovery and port scanning
- **masscan_scan** - High-speed port scanning
- **workflow_enum** - Automated network enumeration

### 🌐 Web Tools
- **ffuf_fuzz** - Fast web directory/file fuzzing
- **gobuster_scan** - Directory and DNS enumeration
- **nikto_scan** - Web vulnerability scanning

### 🔐 Password Tools (Dangerous Mode)
- **john_crack** - Password hash cracking
- **hydra_bruteforce** - Network service brute forcing

### 🤖 Workflow Tools
- **workflow_scan** - Multi-phase vulnerability scanning
- **workflow_report** - Professional report generation

### 💾 System Tools
- **filesystem_ops** - Secure file management
- **command_runner** - Sanitized command execution

### 🔌 Plugin Tools
- **plugin_system** - Dynamic tool management
- **ssl_analyzer** - SSL/TLS security analysis (example plugin)

### 📚 Help Tools
- **help_system** - Interactive documentation and guidance

## 🔍 Troubleshooting

### Server Won't Start

```powershell
# Check if all dependencies are installed
pnpm install

# Rebuild the project
pnpm build

# Check for syntax errors
node --check dist/server.js
```

### Cursor AI Can't Find Server

1. **Verify Paths**: Ensure all paths in configuration are absolute and correct
2. **Check Permissions**: Ensure Cursor can execute node and access the project directory
3. **Environment Variables**: Verify JAIL_ROOT directory exists and is writable

### Tools Not Working

1. **Check Jail Directory**: Ensure `vol` directory exists and is accessible
2. **Verify Dangerous Mode**: Some tools require `DANGEROUS_MODE=true`
3. **Check Logs**: Look at Cursor's developer console for MCP errors

### Performance Issues

1. **Enable Caching**: Caching is enabled by default for better performance
2. **Adjust Timeouts**: Increase timeouts for complex operations
3. **Limit Concurrent Operations**: Use sequential execution for resource-intensive tasks

## 📊 Expected Behavior in Cursor AI

### Beginner Mode (Default)
- Detailed explanations for each tool
- Safety warnings for dangerous operations
- Step-by-step guidance
- Contextual recommendations

### Advanced Mode
- Concise technical output
- Advanced parameter suggestions
- Complex workflow orchestration
- Performance optimization tips

### Interactive Features
- **Progress Tracking**: Real-time execution updates
- **Error Handling**: Graceful error recovery and suggestions
- **Adaptive Learning**: Tool recommendations based on context
- **Security Controls**: Automatic safety checks and confirmations

## 🎉 Success Indicators

When properly integrated, you should see:

1. **✅ MCP Server Status**: "RedQuanta MCP" appears in Cursor's MCP servers list
2. **✅ Tool Availability**: `@redquanta-mcp` autocompletes in chat
3. **✅ Tool Execution**: Security tools execute and return formatted results
4. **✅ Help System**: Contextual help and guidance for each tool
5. **✅ Workflow Orchestration**: Multi-tool automation works seamlessly

## 🚀 Next Steps

Once integrated successfully:

1. **Explore Workflows**: Try the automated enumeration and scanning workflows
2. **Custom Plugins**: Develop custom security tools using our plugin architecture
3. **Advanced Features**: Enable dangerous mode for comprehensive testing
4. **Integration**: Connect with CI/CD pipelines using SARIF reporting
5. **Community**: Share your custom tools and workflows with the community

## 📞 Support

If you encounter issues:

1. **Check Logs**: Enable debug logging for detailed error information
2. **GitHub Issues**: Report bugs and feature requests
3. **Discord Community**: Get real-time help from other users
4. **Documentation**: Refer to the comprehensive tool documentation

---

**🎯 Ready to start intelligent penetration testing with Cursor AI!**

Remember: Always ensure you have proper authorization before testing any systems. RedQuanta MCP is designed for authorized security assessments only. 