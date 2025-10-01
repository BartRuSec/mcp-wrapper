import { spawn } from 'child_process';
import { platform } from 'os';
import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ToolDefinition, CommandResult, TemplateContext, PlatformCommands } from '../types/config.js';
import { renderTemplate, renderSecureTemplate, SecureTemplateContext } from '../templating/mustache.js';
import { SecurityPolicyManager } from '../security/policies.js';
import { createContextLogger } from '../utils/logger.js';

const logger = createContextLogger('tools');

export const createMCPToolFromDefinition = (name: string, definition: ToolDefinition): Tool => {
  return {
    name: definition.name || name,
    description: definition.description,
    inputSchema: definition.input
  };
};

export const getPlatformCommand = (cmd: string | PlatformCommands): string => {
  if (typeof cmd === 'string') {
    return cmd;
  }

  const currentPlatform = platform();

  if (currentPlatform === 'win32' && cmd.win) {
    return cmd.win;
  }

  if (currentPlatform === 'darwin' && cmd.macos) {
    return cmd.macos;
  }

  if ((currentPlatform === 'linux' || currentPlatform === 'freebsd') && cmd.unix) {
    return cmd.unix;
  }

  if (cmd.default) {
    return cmd.default;
  }

  throw new Error(`No command defined for platform: ${currentPlatform}`);
};

export const getShellCommand = (): { shell: string; args: string[] } => {
  const currentPlatform = platform();

  if (currentPlatform === 'win32') {
    return { shell: 'cmd', args: ['/c'] };
  }

  return { shell: 'sh', args: ['-c'] };
};

export const executeShellCommand = async (
  command: string | PlatformCommands,
  context: TemplateContext,
  timeout = 30000
): Promise<CommandResult> => {
  const platformCommand = getPlatformCommand(command);
  const renderedCommand = renderTemplate(platformCommand, context);
  const { shell, args } = getShellCommand();

  logger.debug(`Executing command: ${renderedCommand}`);

  return new Promise((resolve) => {
    const child = spawn(shell, [...args, renderedCommand], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      const result: CommandResult = {
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: code || 0,
        success: (code || 0) === 0
      };

      logger.debug(`Command completed with exit code: ${result.exitCode}`);
      resolve(result);
    });

    child.on('error', (error) => {
      const result: CommandResult = {
        stdout: '',
        stderr: error.message,
        exitCode: 1,
        success: false
      };

      logger.error(`Command execution failed: ${error.message}`);
      resolve(result);
    });
  });
};

export const executeSecureShellCommand = async (
  command: string | PlatformCommands,
  context: TemplateContext,
  inputSchema: any,
  secureContext: SecureTemplateContext,
  timeout?: number
): Promise<CommandResult> => {
  try {
    const platformCommand = getPlatformCommand(command);
    const renderedCommand = renderSecureTemplate(platformCommand, context, secureContext, inputSchema);
    const actualTimeout = timeout || secureContext.policyManager.getMaxExecutionTimeout();

    const { shell, args } = getShellCommand();

    logger.info(`Executing secure command with timeout: ${actualTimeout}ms`);
    logger.debug(`Secure command: ${renderedCommand}`);

    return new Promise((resolve) => {
      const child = spawn(shell, [...args, renderedCommand], {
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: actualTimeout
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data) => {
        stdout += data.toString();

        if (stdout.length > secureContext.policyManager.getPolicy().maxInputLength) {
          logger.warn('Command output exceeding length limits, truncating');
          child.kill('SIGTERM');
        }
      });

      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('close', (code) => {
        const result: CommandResult = {
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          exitCode: code || 0,
          success: (code || 0) === 0
        };

        if (secureContext.policyManager.isAuditLoggingEnabled()) {
          logger.info(`AUDIT: Command executed - Exit Code: ${result.exitCode}, Success: ${result.success}`);
        }

        logger.debug(`Secure command completed with exit code: ${result.exitCode}`);
        resolve(result);
      });

      child.on('error', (error) => {
        const result: CommandResult = {
          stdout: '',
          stderr: error.message,
          exitCode: 1,
          success: false
        };

        if (secureContext.policyManager.isAuditLoggingEnabled()) {
          logger.error(`AUDIT: Command execution failed - Error: ${error.message}`);
        }

        logger.error(`Secure command execution failed: ${error.message}`);
        resolve(result);
      });
    });
  } catch (error) {
    logger.error(`Secure command preparation failed: ${error.message}`);
    return {
      stdout: '',
      stderr: `Security validation failed: ${error.message}`,
      exitCode: 1,
      success: false
    };
  }
};

export const createToolExecutor = (definition: ToolDefinition) => {
  return async (input: TemplateContext): Promise<CommandResult> => {
    try {
      return await executeShellCommand(definition.cmd, input);
    } catch (error) {
      logger.error(`Tool execution failed: ${error.message}`);
      return {
        stdout: '',
        stderr: error.message,
        exitCode: 1,
        success: false
      };
    }
  };
};

export const createSecureToolExecutor = (
  definition: ToolDefinition,
  policyManager: SecurityPolicyManager
) => {
  const allowedPaths = policyManager.getPolicy().allowedPaths;
  const escapeMode = definition.escapeMode || policyManager.getDefaultEscapeMode();
  const secureContext: SecureTemplateContext = { allowedPaths, policyManager, escapeMode };

  return async (input: TemplateContext): Promise<CommandResult> => {
    try {
      return await executeSecureShellCommand(
        definition.cmd,
        input,
        definition.input,
        secureContext
      );
    } catch (error) {
      logger.error(`Secure tool execution failed: ${error.message}`);
      return {
        stdout: '',
        stderr: error.message,
        exitCode: 1,
        success: false
      };
    }
  };
};