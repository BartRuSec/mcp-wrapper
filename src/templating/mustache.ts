import Mustache from 'mustache';
import { TemplateContext } from '../types/config.js';
import { preprocessContext, getEscapeFunction } from '../security/sanitizer.js';
import { SecurityPolicyManager } from '../security/policies.js';
import { createContextLogger } from '../utils/logger.js';

const logger = createContextLogger('template');

export interface SecureTemplateContext {
  allowedPaths: string[];
  policyManager: SecurityPolicyManager;
  escapeMode: 'quote' | 'remove';
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
    const { sanitizedContext, warnings } = preprocessContext(context, inputSchema, secureContext.allowedPaths);

    if (warnings.length > 0) {
      logger.warn(`Template rendering warnings: ${warnings.join('; ')}`);
    }

    if (warnings.length > 0 && secureContext.policyManager.shouldFailOnWarnings()) {
      throw new Error(`Template validation warnings treated as errors: ${warnings.join('; ')}`);
    }

    const escapeFunction = getEscapeFunction(secureContext.escapeMode);
    const rendered = Mustache.render(template, sanitizedContext, {}, {
      escape: escapeFunction
    });

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