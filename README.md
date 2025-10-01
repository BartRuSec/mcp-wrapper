# MCP Wrapper

**MCP Wrapper for shell command line tools** - Expose shell command line tools as MCP (Model Context Protocol) servers through simple YAML configuration.

## Overview

MCP Wrapper allows you to easily create MCP servers that wrap shell command line tools. Define your tools in a simple YAML configuration file and expose them as MCP tools that can be used by AI assistants and other MCP clients.

## Features

- 🔧 **Easy Configuration**: Define tools using simple YAML configuration
- 🌐 **Cross-Platform Support**: Platform-specific commands for Windows, macOS, and Unix/Linux
- 📝 **Mustache Templating**: Dynamic command generation with input parameters
- 🛡️ **Input Validation**: JSON Schema-based input validation using MCP SDK
- 🔒 **Advanced Security**: Multi-layer security with configurable policies and sanitization
- 📊 **Comprehensive Logging**: Winston-based logging with configurable levels
- ⚡ **Official MCP SDK**: Built on the official `@modelcontextprotocol/sdk`
- 🚀 **CLI Ready**: Complete CLI tool with commander.js

## Installation

### Global Installation (Recommended)
```bash
npm install -g mcp-wrapper
```

### Local Installation
```bash
npm install mcp-wrapper
```

### Development Installation
```bash
git clone <repository-url>
cd mcp-wrapper
npm install
npm run build
```

## Quick Start

1. **Create a configuration file** (`mcp-wrapper.yaml`):
```yaml
tools:
  calc:
    description: "Mathematical calculator based on bc command line"
    input:
      type: object
      properties:
        equation:
          description: "bc compatible equation"
          type: string
      required: [equation]
    cmd: "echo {{equation}} | bc -l"
```

2. **Start the MCP server**:
```bash
mcp-wrapper --config mcp-wrapper.yaml
```

3. **Test thoroughly** with various inputs to ensure security:
```bash
# Test with debug logging to see security actions
mcp-wrapper --config mcp-wrapper.yaml --log-level debug
```

4. **Use with an MCP client** or test with the official MCP tools.

## CLI Usage

```bash
mcp-wrapper [options]

Options:
  -c, --config <file>           Configuration file path (default: "mcp-wrapper.yaml")
  --timeout <seconds>           Command execution timeout in seconds (default: "30")
  --name <name>                 Server name
  --version-server <version>    Server version
  --log-level <level>           Log level: error|warn|info|debug (default: "info")
  -V, --version                 Display version number
  -h, --help                    Display help information
```

**Note**: Currently only stdio transport is supported.

### Examples

```bash
# Start with default config file
mcp-wrapper

# Start with custom config
mcp-wrapper --config tools.yaml

# Start with debug logging
mcp-wrapper --config tools.yaml --log-level debug

# Start with custom server name and timeout
mcp-wrapper --config tools.yaml --name "My Tools Server" --timeout 60
```

## Configuration Format

### Basic Structure

```yaml
tools:
  <tool_name>:
    name: <optional_display_name>
    description: <tool_description>
    input:
      type: object
      properties:
        <property_name>:
          type: <property_type>
          description: <property_description>
          default: <optional_default_value>
      required: [<required_property_names>]
    cmd: <shell_command_with_mustache_templates>
```

### Cross-Platform Commands

For cross-platform compatibility, you can specify different commands for different operating systems:

```yaml
tools:
  file_list:
    description: "List files in directory"
    input:
      type: object
      properties:
        path:
          type: string
          description: "Directory path"
          default: "."
    cmd:
      win: "dir {{path}}"
      unix: "ls -la {{path}}"
      macos: "ls -la {{path}}"
      default: "ls {{path}}"
```

**Platform Keys:**
- `win`: Windows (platform() === 'win32')
- `macos`: macOS (platform() === 'darwin')
- `unix`: Unix/Linux (platform() === 'linux' or 'freebsd')
- `default`: Fallback for any platform

### Input Schema Types

Supported property types:
- `string`: Text input
- `number`: Floating point number
- `integer`: Whole number
- `boolean`: True/false value
- `array`: List of values

**Property Options:**
- `description`: Help text for the property
- `default`: Default value if not provided
- `enum`: Allowed values list
- `minimum`/`maximum`: Numeric constraints
- `minLength`/`maxLength`: String length constraints
- `pattern`: Regular expression validation

### Mustache Templating

Commands support Mustache templating with input parameters:

```yaml
cmd: "echo {{expression}} | bc -l"
```

**Template Features:**
- Variable substitution: `{{variable}}`
- Nested properties: `{{object.property}}`
- Automatic escaping for shell safety
- Error on missing variables

## Examples

### Calculator Tool

```yaml
tools:
  calc:
    description: "Mathematical calculator based on bc command line"
    input:
      type: object
      properties:
        equation:
          description: "bc compatible equation"
          type: string
      required: [equation]
    cmd: "echo {{equation}} | bc -l"
```

### Cross-Platform File Search

```yaml
tools:
  file_search:
    name: "File Search Tool"
    description: "Search for files with cross-platform support"
    input:
      type: object
      properties:
        directory:
          type: string
          description: "Directory to search in"
          default: "."
        pattern:
          type: string
          description: "File name pattern"
      required: [pattern]
    cmd:
      win: "forfiles /p {{directory}} /m {{pattern}} /c \"cmd /c echo @path\""
      unix: "find {{directory}} -name '{{pattern}}'"
      macos: "find {{directory}} -name '{{pattern}}'"
```

### Git Repository Info

```yaml
tools:
  git_status:
    name: "Git Repository Status"
    description: "Get Git repository information"
    input:
      type: object
      properties:
        repository_path:
          type: string
          description: "Path to git repository"
          default: "."
        operation:
          type: string
          description: "Git operation to perform"
          enum: ["status", "branch", "log", "diff"]
          default: "status"
        limit:
          type: integer
          description: "Limit for log entries"
          default: 5
          minimum: 1
          maximum: 100
    cmd: "cd {{repository_path}} && case {{operation}} in 'status') git status --porcelain;; 'branch') git branch -v;; 'log') git log --oneline -{{limit}};; 'diff') git diff --stat;; esac"
```

## Documentation

- **[Security Guide](docs/security.md)**: Comprehensive security documentation including security levels, types, and best practices
- **[Examples](examples/)**: Ready-to-use configuration examples for various use cases

## Programmatic Usage

You can also use MCP Wrapper as a library:

```typescript
import { MCPWrapperServer, loadConfig } from 'mcp-wrapper';

// Load configuration
const config = loadConfig('./my-tools.yaml');

// Create server options (stdio transport is used by default)
const options = {
  configFile: './my-tools.yaml',
  name: 'My Custom Server',
  version: '1.0.0'
};

// Create and start server
const server = new MCPWrapperServer(config, options);
await server.start();
```

## Security

This tool executes shell commands and carries inherent security risks. Users are responsible for testing configurations and implementing appropriate security measures.

**📖 See [docs/security.md](docs/security.md) for complete security configuration guide, including:**
- Security levels (strict, moderate, permissive)
- Security types for input sanitization
- Configuration options and examples
- Best practices

## Troubleshooting

### Common Issues

1. **Configuration file not found**
   ```bash
   # Check file path
   ls -la mcp-wrapper.yaml

   # Use absolute path
   mcp-wrapper --config /full/path/to/config.yaml
   ```

2. **Command execution fails**
   ```bash
   # Enable debug logging
   mcp-wrapper --log-level debug

   # Test command manually
   echo "2+2" | bc -l
   ```

3. **Platform-specific commands not working**
   ```bash
   # Check platform detection
   node -e "console.log(require('os').platform())"
   ```

### Security Testing

**Always test your tools with potentially malicious inputs:**

```bash
# Test with debug logging to see security sanitization
mcp-wrapper --config tools.yaml --log-level debug

# Test with strict security level first
security:
  level: strict
  auditLogging: true
```

**Example security test inputs:**
- Command injection: `; rm -rf /`
- Path traversal: `../../../etc/passwd`
- Command substitution: `$(dangerous_command)`
- Special characters: `|&;$()<>`

### Debugging

Enable debug logging to see detailed execution information:

```bash
mcp-wrapper --config tools.yaml --log-level debug
```

This will show:
- Configuration loading details
- Tool registration information
- Security sanitization actions
- Command execution with rendered templates
- Error details and stack traces

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Development Setup

```bash
git clone <repository-url>
cd mcp-wrapper
npm install
npm run dev  # Development mode
npm run build  # Build for production
npm test  # Run tests
```
## Development Tools

This tool has been developed in a hybrid mode, where the core architecture and logic were hand-crafted, while some parts of the implementation were created with the assistance of various LLM models and tools.

## License

MPL-2.0 License - see LICENSE file for details.

## Support

- 🐛 **Issues**: Report bugs and request features on GitHub
- 📖 **Documentation**:
  - [Security Guide](docs/security.md) for security configuration
  - [Examples](examples/) directory for configuration samples
- 💬 **Discussions**: Join the MCP community discussions