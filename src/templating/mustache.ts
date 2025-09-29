import Mustache from 'mustache';
import { TemplateContext } from '../types/config.js';
import { InputValidator } from '../security/validator.js';
import { SecurityPolicyManager } from '../security/policies.js';
import { createContextLogger } from '../utils/logger.js';

const logger = createContextLogger('template');

export interface SecureTemplateContext {
  validator: InputValidator;
  policyManager: SecurityPolicyManager;
}

export const renderTemplate = (template: string, context: TemplateContext): string => {
  try {
    return Mustache.render(template, context);
  } catch (error) {
    throw new Error(`Template rendering failed: ${error.message}`);
  }
};

export const renderSecureTemplate = (
  template: string,
  context: TemplateContext,
  secureContext: SecureTemplateContext,
  inputSchema: any
): string => {
  try {
    // Extract validation rules from input schema
    const { validation } = secureContext.validator.extractValidationRules(inputSchema);

    // Validate and sanitize all input values (MCP already validated schema constraints)
    const validationResults = secureContext.validator.validateInput(context, validation);

    // Check for validation errors
    const errors: string[] = [];
    const warnings: string[] = [];
    const sanitizedContext: TemplateContext = {};

    for (const [key, result] of Object.entries(validationResults)) {
      if (!result.valid) {
        errors.push(`${key}: ${result.errors.join(', ')}`);
      }
      if (result.warnings.length > 0) {
        warnings.push(`${key}: ${result.warnings.join(', ')}`);
      }
      sanitizedContext[key] = result.sanitizedValue;
    }

    // Log warnings
    if (warnings.length > 0) {
      logger.warn(`Template rendering warnings: ${warnings.join('; ')}`);
    }

    // Fail on errors or warnings if policy requires it
    if (errors.length > 0) {
      throw new Error(`Template validation failed: ${errors.join('; ')}`);
    }

    if (warnings.length > 0 && secureContext.policyManager.shouldFailOnWarnings()) {
      throw new Error(`Template validation warnings treated as errors: ${warnings.join('; ')}`);
    }

    // Validate the template itself doesn't contain blocked patterns
    if (secureContext.policyManager.isPatternBlocked(template)) {
      throw new Error('Template contains blocked patterns');
    }

    // Render with sanitized context
    const rendered = Mustache.render(template, sanitizedContext);

    // Final check on rendered command
    if (secureContext.policyManager.isPatternBlocked(rendered)) {
      throw new Error('Rendered command contains blocked patterns');
    }

    logger.debug(`Securely rendered template: ${rendered}`);
    return rendered;

  } catch (error) {
    logger.error(`Secure template rendering failed: ${error.message}`);
    throw error;
  }
};

export const validateTemplate = (template: string): string[] => {
  const errors: string[] = [];

  try {
    Mustache.parse(template);
  } catch (error) {
    errors.push(`Invalid mustache template: ${error.message}`);
  }

  return errors;
};

export const extractTemplateVariables = (template: string): string[] => {
  const parsed = Mustache.parse(template);
  const variables: string[] = [];

  const extractFromTokens = (tokens: any[]): void => {
    tokens.forEach(token => {
      if (token[0] === 'name') {
        if (!variables.includes(token[1])) {
          variables.push(token[1]);
        }
      } else if (token[4]) {
        extractFromTokens(token[4]);
      }
    });
  };

  extractFromTokens(parsed);
  return variables;
};