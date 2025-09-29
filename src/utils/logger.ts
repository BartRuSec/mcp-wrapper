import winston from 'winston';
import chalk from 'chalk';

const { combine, timestamp, printf, colorize } = winston.format;

const customFormat = printf(({ level, message, timestamp }) => {
  const time = new Date(timestamp as string).toISOString().substring(11, 19);
  return `${chalk.gray(time)} ${level}: ${message}`;
});

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    timestamp(),
    colorize(),
    customFormat
  ),
  transports: [
    new winston.transports.Console({
      stderrLevels: ['error', 'warn']
    })
  ]
});

export const setLogLevel = (level: string): void => {
  logger.level = level;
};

export const createContextLogger = (context: string) => {
  return {
    error: (message: string, ...args: any[]) => logger.error(`[${context}] ${message}`, ...args),
    warn: (message: string, ...args: any[]) => logger.warn(`[${context}] ${message}`, ...args),
    info: (message: string, ...args: any[]) => logger.info(`[${context}] ${message}`, ...args),
    debug: (message: string, ...args: any[]) => logger.debug(`[${context}] ${message}`, ...args)
  };
};