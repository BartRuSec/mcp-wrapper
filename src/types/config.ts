import { ServerCapabilities } from '@modelcontextprotocol/sdk/types.js';
import { SecurityLevel } from '../security/policies.js';

export interface MCPConfig {
  tools: Record<string, ToolDefinition>;
  security?: SecurityConfig;
}

export interface SecurityConfig {
  level?: SecurityLevel;
  allowedPaths?: string[];
  maxExecutionTimeout?: number;
  maxInputLength?: number;
  auditLogging?: boolean;
  failOnWarnings?: boolean;
}

export interface ServerOptions {
  name?: string;
  version?: string;
  capabilities?: ServerCapabilities;
  configFile: string;
}

export interface ToolDefinition {
  name?: string;
  description: string;
  input: ExtendedInputSchema;
  cmd: string | PlatformCommands;
  escapeMode?: 'quote' | 'remove';
}

export interface ExtendedInputSchema {
  [x: string]: unknown;
  type: 'object';
  properties?: Record<string, ExtendedPropertySchema>;
  required?: string[];
  description?: string;
}

export interface ExtendedPropertySchema {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object';
  description?: string;
  default?: any;
  enum?: (string | number | boolean)[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  // Security extension - only for filepath pre-sanitization
  security?: 'filepath';
}

export interface PlatformCommands {
  win?: string;
  macos?: string;
  unix?: string;
  default?: string;
}

export interface TemplateContext {
  [key: string]: any;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  success: boolean;
}

export interface ConfigValidationError {
  field: string;
  message: string;
  value?: any;
}

export interface LoadConfigOptions {
  validateSchema?: boolean;
  allowMissingFile?: boolean;
  defaults?: Partial<MCPConfig>;
}

export const DEFAULT_SERVER_OPTIONS: Partial<ServerOptions> = {};