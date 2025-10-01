# Security Guide

> **⚠️ SECURITY DISCLAIMER**
>
> This tool executes shell commands based on configuration and user input. Command execution carries inherent security risks. Users are responsible for:
> - Testing configurations thoroughly before deployment
> - Understanding security implications of their commands
> - Implementing appropriate additional security measures (sandboxing, containers, network isolation, etc.)
> - Regular security reviews and monitoring
>
> The maintainers are not responsible for security incidents, data loss, or damage caused by use of this software.

## Security Model

MCP Wrapper uses a simple, transparent security model:

### Trust Model

- **Config files are trusted**: Commands in your YAML config are treated as application code and not validated
- **User inputs are untrusted**: All runtime inputs are shell-escaped before template rendering
- **Shell escaping via Mustache**: The Mustache escaper is customized to perform shell quoting (not HTML escaping)
- **Optional filepath sanitization**: Properties marked `security: filepath` get path traversal protection

### How It Works

1. **Configuration time**: Validates YAML syntax, template syntax, and input schemas
2. **Runtime**:
   - Pre-sanitizes any `security: filepath` properties (removes `..`, validates against `allowedPaths`)
   - Shell-escapes all `{{variable}}` substitutions using the configured escape mode
   - Renders the template with escaped values
   - Executes with timeout limits

**No command validation**: There's no pattern blocking, no allowlists, no command analysis. Security comes from properly escaping user inputs.

## Security Levels

Three predefined levels control timeouts, limits, and default escape mode:

| Level | Default Escape | Timeout | Max Input | Allowed Paths | Audit Log | Fail on Warnings |
|-------|----------------|---------|-----------|---------------|-----------|------------------|
| **strict** | `remove` | 10s | 1000 chars | `./` only | ✅ | ✅ |
| **moderate** | `quote` | 30s | 5000 chars | `./`, temp, home (OS-aware) | ✅ | ❌ |
| **permissive** | `quote` | 60s | 10000 chars | All paths | ❌ | ❌ |

**Default**: If you don't specify a security level, `moderate` is used.

## Escape Modes

All `{{variable}}` substitutions are shell-escaped. You control *how* with `escapeMode`:

### Quote Mode (default for moderate/permissive)

```yaml
tools:
  my_tool:
    escapeMode: quote  # Default for moderate/permissive levels
```

- Wraps input in shell quotes (single quotes on Unix, double on Windows)
- Preserves all characters, making them literal
- Example: `hello & goodbye` → `'hello & goodbye'`
- The `&` becomes literal text, not a shell operator

### Remove Mode (default for strict)

```yaml
tools:
  my_tool:
    escapeMode: remove  # Default for strict level
```

- Strips dangerous characters: `[;&|`$(){}[\]]` and newlines
- Then applies shell quoting
- Example: `hello & goodbye` → `'hello  goodbye'`
- The `&` is removed entirely

### Raw/Unescaped (not recommended)

```yaml
cmd: "echo {{safe}} && {{{unsafe}}}"
```

- `{{variable}}` - Shell-escaped (safe)
- `{{{variable}}}` - Raw, no escaping (**dangerous**, can execute arbitrary commands)

**Avoid `{{{}}}`** unless absolutely necessary.

## File Path Security

For properties accepting file paths, use `security: filepath`:

```yaml
properties:
  file_path:
    type: string
    security: filepath
```

**What it does:**
- Removes dangerous shell characters
- Normalizes the path
- Blocks `..` path traversal (reduces to basename only)
- Validates against `allowedPaths` (reduces to basename if not allowed)
- Applies shell quoting

**Examples:**
- Input: `../../../etc/passwd` → Output: `'passwd'` (traversal blocked)
- Input: `/etc/passwd` (strict policy) → Output: `'passwd'` (not in allowed paths)

## Configuration

### Basic Configuration

```yaml
security:
  level: moderate  # strict | moderate | permissive
```

### Custom Configuration

Override specific settings:

```yaml
security:
  level: strict
  maxExecutionTimeout: 5  # Override timeout
  allowedPaths: ["./data/", "./scripts/"]  # Override paths
```

### Tool-Level Escape Mode

```yaml
tools:
  production_tool:
    description: "Tool for production"
    escapeMode: remove  # Override security level default
    input:
      properties:
        message:
          type: string
    cmd: "echo {{message}}"
```

## Examples

### Example 1: Calculator

```yaml
security:
  level: strict

tools:
  calc:
    description: "Calculator"
    escapeMode: quote  # Override to preserve math operators
    input:
      properties:
        expression:
          type: string
      required: [expression]
    cmd: "echo '{{expression}}' | bc -l"
```

### Example 2: File Reader

```yaml
security:
  level: moderate
  allowedPaths: ["./data/"]

tools:
  read_file:
    description: "Read file contents"
    input:
      properties:
        file_path:
          type: string
          security: filepath
        lines:
          type: integer
          maximum: 1000
      required: [file_path]
    cmd: "head -n {{lines}} {{file_path}}"
```

### Example 3: Command Runner

```yaml
tools:
  run_command:
    description: "Run shell command"
    input:
      properties:
        command:
          type: string
      required: [command]
    cmd: "{{{command}}}"
```

**Note**: Using `{{{variable}}}` allows raw input - understand the security implications before using.

## Best Practices

1. **Use `security: filepath` for file paths**
   ```yaml
   properties:
     path:
       type: string
       security: filepath
   ```

2. **Avoid `{{{ }}}` (raw/unescaped)**
   ```yaml
   # ❌ Dangerous
   cmd: "run {{{user_input}}}"

   # ✅ Safe
   cmd: "run {{user_input}}"
   ```

3. **Use JSON Schema constraints**
   ```yaml
   properties:
     count:
       type: integer
       minimum: 1
       maximum: 100  # Prevent abuse
     action:
       type: string
       enum: [read, list, info]
   ```

4. **Test with malicious inputs**
   ```bash
   # Test command injection
   echo '{"input": "test; rm -rf /"}' | mcp-wrapper --config config.yaml

   # See security actions
   mcp-wrapper --config config.yaml --log-level debug
   ```

5. **Consider additional security layers** (containers, sandboxing, network isolation)

## Security Implementation Details

### What's Validated at Config Load

- Template syntax (Mustache)
- YAML syntax
- Required fields (description, cmd, input)
- Input schemas (JSON Schema)
- `escapeMode` values (`quote` or `remove`)
- `security` values (`filepath` or omit)

Commands in config are treated as trusted code and not validated.

### What Happens at Runtime

1. **JSON Schema validation** (via MCP SDK)
2. **Filepath pre-sanitization** (if `security: filepath`)
3. **Shell escaping** (all `{{variables}}` via Mustache custom escaper)
4. **Template rendering** (substitution with escaped values)
5. **Execution** (with timeout enforcement)

Security comes from proper input escaping before rendering.

### Error Examples

**Config errors:**
```yaml
# Invalid escape mode
escapeMode: invalid  # Error: must be 'quote' or 'remove'

# Invalid security type
security: unsafe  # Error: must be 'filepath' or omit
```

**Runtime errors:**
```json
{
  "error": "Path traversal blocked",
  "property": "file_path",
  "value": "../../etc/passwd"
}
```

## Security Checklist

- [ ] Choose appropriate security level
- [ ] Configure `auditLogging` based on your needs
- [ ] Use `security: filepath` for all file path inputs
- [ ] Avoid `{{{ }}}` raw substitution unless necessary
- [ ] Set JSON Schema constraints (min/max, enum)
- [ ] Configure `allowedPaths` for file operations if needed
- [ ] Test with malicious inputs
- [ ] Consider containerization/sandboxing for additional protection
- [ ] Review logs regularly if audit logging is enabled
- [ ] Protect config files with appropriate file permissions

## Additional Resources

- [Main README](../README.md) - Configuration examples and quick start
- [Examples Directory](../examples/) - Sample configurations
