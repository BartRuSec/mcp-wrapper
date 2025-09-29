# Security Guide

> **⚠️ IMPORTANT SECURITY DISCLAIMER**
>
> **This tool is under active development and the security system, while comprehensive, should not be considered foolproof.** Users must exercise extreme caution when creating MCP tools that execute command line operations and should thoroughly test all configurations in safe environments.
>
> **Critical Security Warnings:**
> - The security system may have undiscovered vulnerabilities
> - No security system can protect against all possible attack vectors
> - Command line execution inherently carries security risks
> - User input sanitization may not catch all malicious patterns
> - System commands can have platform-specific security implications
>
> **Users are responsible for:**
> - Thoroughly testing their configurations with various inputs
> - Understanding the security implications of their tool configurations
> - Implementing additional security measures as needed (sandboxing, containers, etc.)
> - Regular security reviews and updates
> - Monitoring for suspicious activity
>
> **Use this tool at your own risk. The maintainers are not responsible for any security incidents, data loss, or damage caused by use of this software.**

MCP Wrapper includes a comprehensive security system designed to protect against command injection, malicious input, and other security vulnerabilities while maintaining usability for legitimate use cases.

## Table of Contents

- [Overview](#overview)
- [Security Levels](#security-levels)
- [Security Types](#security-types)
- [Configuration](#configuration)
- [Default Security Behavior](#default-security-behavior)
- [Advanced Security Features](#advanced-security-features)
- [Security Examples](#security-examples)
- [Best Practices](#best-practices)
- [Security Validation](#security-validation)

## Overview

The security system operates on multiple layers:

1. **Input Validation**: JSON schema validation handled by MCP SDK
2. **Security Sanitization**: Command injection prevention and input sanitization
3. **Policy Enforcement**: Configurable security policies for different environments
4. **Command Validation**: Template validation and execution safety checks
5. **Audit Logging**: Security event logging for monitoring and compliance

## Security Levels

MCP Wrapper provides three predefined security levels that balance security and usability:

### Strict Security Level

**Use Case**: Production environments, public-facing tools, high-security requirements

**Configuration**:
- **Default Security Type**: `safe`
- **Allow Unsafe**: `false`
- **Allowed Commands**: Limited whitelist (echo, cat, ls, pwd, whoami, date, bc, grep, awk, sed, sort, uniq, wc, head, tail)
- **Blocked Patterns**: Comprehensive list of dangerous patterns
- **Max Execution Timeout**: 10 seconds
- **Max Input Length**: 1000 characters
- **Audit Logging**: `true`
- **Fail on Warnings**: `true` (warnings are treated as errors)

**Blocked Patterns**:
```
\\|, &&, ||, ;, `, $(, ${, rm , del , format, mkfs, dd , chmod, chown, sudo, su , passwd
```

### Moderate Security Level (Default)

**Use Case**: Development environments, trusted internal tools, balanced security

**Configuration**:
- **Default Security Type**: `safe`
- **Allow Unsafe**: `false`
- **Allowed Commands**: Extended whitelist including development tools (git, curl, wget, ping, nslookup)
- **Blocked Patterns**: Focused on obviously dangerous operations
- **Max Execution Timeout**: 30 seconds
- **Max Input Length**: 5000 characters
- **Audit Logging**: `true`
- **Fail on Warnings**: `false` (warnings are logged but don't block execution)

**Blocked Patterns**:
```
rm -rf, del /s, format, mkfs, dd if=, sudo rm, su -, passwd
```

### Permissive Security Level

**Use Case**: Development environments, specialized tools, maximum functionality

**Configuration**:
- **Default Security Type**: `safe`
- **Allow Unsafe**: `true`
- **Allowed Commands**: All commands allowed (empty whitelist)
- **Blocked Patterns**: Only extremely dangerous operations
- **Max Execution Timeout**: 60 seconds
- **Max Input Length**: 10000 characters
- **Audit Logging**: `false`
- **Fail on Warnings**: `false`

**Blocked Patterns**:
```
rm -rf /, del /s /q C:\\, format C:, mkfs, dd if=/dev/zero
```

## Security Types

Security types define how input parameters are sanitized before being used in shell commands:

### `safe` (Default)

**Purpose**: General-purpose safe input sanitization

**Behavior**:
- Removes dangerous shell characters: `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `{`, `}`, `[`, `]`
- Converts newlines to spaces
- Applies platform-specific shell quoting
- HTML escapes output for additional safety

**Example**:
```yaml
properties:
  message:
    type: string
    security: safe  # Optional - this is the default
```

### `filepath`

**Purpose**: File path validation and sanitization

**Behavior**:
- Removes dangerous characters
- Normalizes paths to prevent traversal attacks
- Blocks absolute paths (forces relative paths)
- Blocks `..` path traversal attempts
- Applies shell quoting

**Example**:
```yaml
properties:
  file_path:
    type: string
    security: filepath
```

**Input**: `../../../etc/passwd`
**Output**: `'passwd'` (path traversal blocked, basename only)

### `command`

**Purpose**: Command name validation

**Behavior**:
- Validates against allowed command whitelist
- Blocks dangerous commands
- Sanitizes command arguments
- Applies shell quoting to arguments

**Example**:
```yaml
properties:
  command:
    type: string
    security: command
```

### `text`

**Purpose**: Text content that may contain special characters

**Behavior**:
- Removes dangerous shell operators: `;`, `&`, `|`, `` ` ``
- Removes command substitution: `$(`, `${`
- Preserves other characters for text content
- Applies shell quoting

**Example**:
```yaml
properties:
  search_text:
    type: string
    security: text
```

### `unsafe`

**Purpose**: No sanitization (use with extreme caution)

**Behavior**:
- No sanitization applied
- Raw input passed through
- Only available when `allowUnsafe: true`
- Generates security warnings

**Example**:
```yaml
security:
  level: permissive
  allowUnsafe: true

tools:
  advanced_tool:
    input:
      properties:
        raw_command:
          type: string
          security: unsafe  # Only with allowUnsafe: true
```

## Configuration

### Basic Security Configuration

```yaml
security:
  level: moderate           # strict, moderate, or permissive
  allowUnsafe: false        # Enable unsafe security type
  auditLogging: true        # Log security events
  maxExecutionTimeout: 30   # Command timeout in seconds
  maxInputLength: 5000      # Maximum input length
  failOnWarnings: false     # Treat warnings as errors
```

### Custom Security Configuration

You can override specific settings while keeping a security level base:

```yaml
security:
  level: strict
  # Override specific settings
  allowedCommands: [echo, bc, date, ls]
  blockedPatterns: []  # Remove all blocked patterns
  maxExecutionTimeout: 5
  allowedPaths: ["./scripts/", "./data/"]
```

### Tool-Specific Security Types

```yaml
tools:
  file_processor:
    description: "Process files with different security requirements"
    input:
      type: object
      properties:
        config_file:
          type: string
          security: filepath  # File path sanitization
        command:
          type: string
          security: command   # Command validation
        search_text:
          type: string
          security: text      # Text sanitization
        safe_input:
          type: string
          security: safe      # General sanitization (default)
      required: [config_file]
```

## Default Security Behavior

When no `security` section is provided in your configuration, MCP Wrapper applies sensible defaults:

```yaml
# Implicit defaults when security section is omitted
security:
  level: moderate
  defaultSecurityType: safe
  allowUnsafe: false
  auditLogging: true
  failOnWarnings: false
  maxExecutionTimeout: 30
  maxInputLength: 5000
```

**Auto-Detection**: Security types are automatically detected based on property names:
- Properties containing "path", "file", or "dir" → `filepath`
- Properties containing "command" or "cmd" → `command`
- All other properties → `safe`

**Example without explicit security**:
```yaml
tools:
  file_tool:
    description: "File operations with auto-detected security"
    input:
      type: object
      properties:
        file_path:      # Auto-detected as 'filepath' security type
          type: string
        message:        # Auto-detected as 'safe' security type
          type: string
```

## Advanced Security Features

### Command Whitelisting

Control which commands are allowed to be executed:

```yaml
security:
  level: strict
  allowedCommands: [echo, cat, ls, grep, awk]
```

**Empty List Behavior**: An empty `allowedCommands` array allows all commands (permissive mode).

### Pattern Blocking

Block specific patterns in commands and input:

```yaml
security:
  level: moderate
  blockedPatterns:
    - "rm -rf"
    - "sudo"
    - "\\$\\("      # Command substitution
    - "eval"
```

### Path Restrictions

Limit file system access to specific directories:

```yaml
security:
  level: strict
  allowedPaths:
    - "./"          # Current directory
    - "./data/"     # Data directory
    - "/tmp/"       # Temporary files
```

### Input Length Limits

Prevent resource exhaustion attacks:

```yaml
security:
  maxInputLength: 1000      # Maximum characters per input
  maxExecutionTimeout: 10   # Maximum seconds per command
```

### Audit Logging

Security events are logged when audit logging is enabled:

```yaml
security:
  auditLogging: true
```

**Logged Events**:
- Security warnings and sanitization actions
- Blocked commands and patterns
- Input validation failures
- Command execution with sanitized parameters

## Security Examples

### Example 1: Basic Calculator (Strict Security)

```yaml
security:
  level: strict
  allowedCommands: [echo, bc]
  blockedPatterns: []  # Override strict defaults for calculator

tools:
  calculator:
    description: "Mathematical calculator with strict security"
    input:
      type: object
      properties:
        expression:
          type: string
          description: "Mathematical expression"
          security: text  # Allow mathematical operators
      required: [expression]
    cmd: "echo 'scale=10; {{expression}}' | bc -l"
```

### Example 2: File Operations (Moderate Security)

```yaml
security:
  level: moderate
  allowedPaths: ["./", "./data/", "/tmp/"]

tools:
  file_reader:
    description: "Read file contents safely"
    input:
      type: object
      properties:
        file_path:
          type: string
          security: filepath  # Path traversal protection
        lines:
          type: integer
          maximum: 1000      # Limit output size
      required: [file_path]
    cmd: "head -n {{lines}} {{file_path}}"
```

### Example 3: Development Tools (Permissive Security)

```yaml
security:
  level: permissive
  allowUnsafe: true
  auditLogging: true

tools:
  git_tool:
    description: "Git operations for development"
    input:
      type: object
      properties:
        repository:
          type: string
          security: filepath
        git_command:
          type: string
          security: unsafe    # Allow complex git commands
      required: [repository, git_command]
    cmd: "cd {{repository}} && {{git_command}}"
```

## Best Practices

### 1. Choose Appropriate Security Level

- **Production**: Use `strict` security level
- **Development**: Use `moderate` security level
- **Specialized Tools**: Use `permissive` only when necessary

### 2. Minimize Unsafe Usage

```yaml
# ❌ Avoid unsafe when possible
properties:
  command:
    security: unsafe

# ✅ Use specific security types
properties:
  command:
    security: command
```

### 3. Use Explicit Security Types

```yaml
# ✅ Explicit security type
properties:
  file_path:
    type: string
    security: filepath

# ⚠️ Relies on auto-detection
properties:
  file_path:
    type: string
```

### 4. Validate Input Constraints

```yaml
properties:
  lines:
    type: integer
    minimum: 1
    maximum: 1000    # Prevent resource exhaustion
  command:
    type: string
    enum: [status, log, diff]  # Limit to safe commands
```

### 5. Enable Audit Logging

```yaml
security:
  auditLogging: true  # Always enable in production
```

### 6. Test Security Configuration

Always test your security configuration with various inputs:

```bash
# Test with malicious input
echo '{"expression": "2+2; rm -rf /"}' | mcp-wrapper --config calc.yaml

# Enable debug logging to see security actions
mcp-wrapper --config calc.yaml --log-level debug
```

## Security Validation

### Configuration Validation

MCP Wrapper validates security configuration at startup:

```bash
# Invalid security level
security:
  level: invalid_level  # Error: must be strict, moderate, or permissive

# Invalid security type
properties:
  input:
    security: invalid_type  # Error: must be safe, filepath, command, text, or unsafe

# Unsafe not allowed
security:
  allowUnsafe: false
properties:
  input:
    security: unsafe  # Error: unsafe not allowed by current policy
```

### Runtime Validation

Security validation occurs at runtime for each tool execution:

1. **Input Schema Validation**: MCP SDK validates against JSON schema
2. **Security Type Validation**: Check if security type is allowed
3. **Input Sanitization**: Apply security type-specific sanitization
4. **Command Validation**: Validate rendered command against policies
5. **Pattern Blocking**: Check for blocked patterns
6. **Execution**: Run sanitized command with timeout

### Error Handling

Security violations result in structured error responses:

```json
{
  "error": "Security validation failed",
  "details": "Command contains blocked patterns",
  "input": "user_provided_input",
  "violations": ["pattern_rm_-rf"]
}
```

## Security Updates

The security system is continuously updated to address new threats:

- **Blocked Patterns**: Updated based on security research
- **Validation Logic**: Enhanced to catch new attack vectors
- **Default Policies**: Adjusted based on real-world usage

For security questions or concerns, please review the codebase or contact the maintainers.