import * as yaml from 'js-yaml';
import { readFileSync, existsSync } from 'fs';
import { MCPConfig, LoadConfigOptions, ConfigValidationError, PlatformCommands } from '../types/config.js';
import { SecurityPolicyManager } from '../security/policies.js';
import { validateTemplate, extractTemplateVariables } from '../templating/mustache.js';
import { createContextLogger } from '../utils/logger.js';

const logger = createContextLogger('config');

export const loadConfig = (configPath: string, options: LoadConfigOptions = {}): MCPConfig => {
  const {
    validateSchema = true,
    allowMissingFile = false
  } = options;

  if (!existsSync(configPath)) {
    if (allowMissingFile) {
      return { tools: {} };
    }
    throw new Error(`Configuration file not found: ${configPath}`);
  }

  try {
    const configContent = readFileSync(configPath, 'utf8');
    const parsedConfig = yaml.load(configContent) as MCPConfig;

    // Normalize tool-level string cmd to cmd.default for consistency
    Object.values(parsedConfig.tools || {}).forEach(tool => {
      if (tool.cmd && typeof tool.cmd === 'string') {
        tool.cmd = { default: tool.cmd };
      }
    });

    if (validateSchema) {
      validateConfig(parsedConfig);
    }

    return parsedConfig;
  } catch (error) {
    if (error instanceof yaml.YAMLException) {
      throw new Error(`Invalid YAML syntax in config file: ${error.message}`);
    }
    throw error;
  }
};

const validateConfig = (config: MCPConfig): void => {
  const errors: ConfigValidationError[] = [];

  // Validate security configuration first
  if (config.security) {
    validateSecurityConfig(config.security, errors);

    // If security validation failed, don't try to create policy manager
    if (errors.length > 0) {
      const errorMessage = errors
        .map(err => `${err.field}: ${err.message}`)
        .join('\n');
      throw new Error(`Configuration validation failed:\n${errorMessage}`);
    }
  }

  // Create security policy manager for validation
  // If no security section is provided, defaults to 'moderate' security level
  const policyManager = config.security
    ? SecurityPolicyManager.fromConfig(config.security)
    : new SecurityPolicyManager(); // Defaults to moderate security level

  if (!config.tools || Object.keys(config.tools).length === 0) {
    errors.push({ field: 'tools', message: 'At least one tool must be defined' });
  } else {
    Object.entries(config.tools).forEach(([toolName, tool]) => {
      if (!tool.description) {
        errors.push({
          field: `tools.${toolName}.description`,
          message: 'Tool description is required'
        });
      }

      if (!tool.cmd) {
        errors.push({
          field: `tools.${toolName}.cmd`,
          message: 'Tool command is required'
        });
      } else {
        validateToolCommand(tool.cmd, `tools.${toolName}.cmd`, errors, policyManager);
      }

      if (!tool.input) {
        errors.push({
          field: `tools.${toolName}.input`,
          message: 'Tool input schema is required'
        });
      } else {
        validateToolInputSchema(tool.input, `tools.${toolName}.input`, errors, policyManager);
      }
    });
  }

  if (errors.length > 0) {
    const errorMessage = errors
      .map(err => `${err.field}: ${err.message}`)
      .join('\n');
    throw new Error(`Configuration validation failed:\n${errorMessage}`);
  }

  logger.info('Configuration validation passed');
};

const validateToolInputSchema = (
  schema: any,
  fieldPath: string,
  errors: ConfigValidationError[],
  policyManager: SecurityPolicyManager
): void => {
  if (schema.type !== 'object') {
    errors.push({
      field: `${fieldPath}.type`,
      message: 'Input schema type must be "object"',
      value: schema.type
    });
  }

  if (schema.properties) {
    Object.entries(schema.properties).forEach(([propName, prop]: [string, any]) => {
      const validTypes = ['string', 'number', 'integer', 'boolean', 'array', 'object'];
      if (!validTypes.includes(prop.type)) {
        errors.push({
          field: `${fieldPath}.properties.${propName}.type`,
          message: `Property type must be one of: ${validTypes.join(', ')}`,
          value: prop.type
        });
      }

      // Validate security type if specified
      if (prop.security) {
        const validSecurityTypes = ['safe', 'filepath', 'command', 'text', 'unsafe'];
        if (!validSecurityTypes.includes(prop.security)) {
          errors.push({
            field: `${fieldPath}.properties.${propName}.security`,
            message: `Security type must be one of: ${validSecurityTypes.join(', ')}`,
            value: prop.security
          });
        } else if (!policyManager.validateSecurityType(prop.security)) {
          errors.push({
            field: `${fieldPath}.properties.${propName}.security`,
            message: `Security type '${prop.security}' not allowed by current security policy`,
            value: prop.security
          });
        }
      }
    });
  }
};

const validateToolCommand = (
  cmd: string | PlatformCommands,
  fieldPath: string,
  errors: ConfigValidationError[],
  policyManager: SecurityPolicyManager
): void => {
  const commands = typeof cmd === 'string' ? [cmd] : Object.values(cmd).filter(Boolean);

  commands.forEach((command, index) => {
    const cmdPath = typeof cmd === 'string' ? fieldPath : `${fieldPath}.${Object.keys(cmd)[index]}`;

    // Validate template syntax
    const templateErrors = validateTemplate(command);
    if (templateErrors.length > 0) {
      errors.push({
        field: cmdPath,
        message: `Template validation failed: ${templateErrors.join(', ')}`,
        value: command
      });
    }

    // Check for blocked patterns
    if (policyManager.isPatternBlocked(command)) {
      errors.push({
        field: cmdPath,
        message: 'Command contains blocked patterns',
        value: command
      });
    }

    // Extract and validate commands if command whitelist is enabled
    const templateVars = extractTemplateVariables(command);
    const commandPart = command.split(' ')[0];

    // Check if base command is allowed (if whitelist is configured)
    if (policyManager.getPolicy().allowedCommands.length > 0) {
      if (!policyManager.isCommandAllowed(commandPart)) {
        errors.push({
          field: cmdPath,
          message: `Command '${commandPart}' not in allowed list`,
          value: command
        });
      }
    }

    logger.debug(`Validated command template with variables: ${templateVars.join(', ')}`);
  });

  // Platform-specific validation
  if (typeof cmd !== 'string') {
    const platforms = ['win', 'macos', 'unix', 'default'];
    const definedPlatforms = Object.keys(cmd).filter(key => platforms.includes(key));

    if (definedPlatforms.length === 0) {
      errors.push({
        field: fieldPath,
        message: 'At least one platform command must be defined (win, macos, unix, or default)'
      });
    }

    definedPlatforms.forEach(platform => {
      if (!cmd[platform as keyof PlatformCommands]) {
        errors.push({
          field: `${fieldPath}.${platform}`,
          message: 'Platform command cannot be empty'
        });
      }
    });
  }
};

const validateSecurityConfig = (security: any, errors: ConfigValidationError[]): void => {
  const validLevels = ['strict', 'moderate', 'permissive'];

  if (security.level && !validLevels.includes(security.level)) {
    errors.push({
      field: 'security.level',
      message: `Security level must be one of: ${validLevels.join(', ')}`,
      value: security.level
    });
  }

  const validSecurityTypes = ['safe', 'filepath', 'command', 'text', 'unsafe'];
  if (security.defaultSecurityType && !validSecurityTypes.includes(security.defaultSecurityType)) {
    errors.push({
      field: 'security.defaultSecurityType',
      message: `Default security type must be one of: ${validSecurityTypes.join(', ')}`,
      value: security.defaultSecurityType
    });
  }

  if (security.maxExecutionTimeout && (typeof security.maxExecutionTimeout !== 'number' || security.maxExecutionTimeout <= 0)) {
    errors.push({
      field: 'security.maxExecutionTimeout',
      message: 'Max execution timeout must be a positive number',
      value: security.maxExecutionTimeout
    });
  }

  if (security.maxInputLength && (typeof security.maxInputLength !== 'number' || security.maxInputLength <= 0)) {
    errors.push({
      field: 'security.maxInputLength',
      message: 'Max input length must be a positive number',
      value: security.maxInputLength
    });
  }
};