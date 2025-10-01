#!/usr/bin/env node

import { Command } from 'commander';
import { existsSync } from 'fs';
import { MCPWrapperServer } from './mcp/server.js';
import { loadConfig } from './config/loader.js';
import { ServerOptions, DEFAULT_SERVER_OPTIONS } from './types/config.js';
import { logger, setLogLevel } from './utils/logger.js';
import { version } from '../package.json';


const program = new Command();

program
  .name('mcp-wrapper')
  .description('MCP Wrapper - Expose shell command line tools as MCP servers')
  .version(version, '-v, --version', 'output the current version');

program
  .option('-c, --config <file>', 'Configuration file path', 'mcp-wrapper.yaml')
  .option('--timeout <seconds>', 'Command execution timeout in seconds', '30')
  .option('--name <name>', 'Server name')
  .option('--version-server <version>', 'Server version')
  .option('--log-level <level>', 'Log level (error|warn|info|debug)', 'warn')
  .action(async (options) => {
    try {
      // Set log level
      setLogLevel(options.logLevel);

      // Validate config file exists
      if (!existsSync(options.config)) {
        logger.error(`Configuration file not found: ${options.config}`);
        process.exit(1);
      }

      // Load configuration
      logger.info(`Loading configuration from: ${options.config}`);
      const config = loadConfig(options.config);


      // Prepare server options
      const serverOptions: ServerOptions = {
        ...DEFAULT_SERVER_OPTIONS,
        configFile: options.config,
        name: options.name,
        version: options.versionServer
      };

      logger.info(`Starting MCP server with stdio transport`);
      logger.info(`Number of tools loaded: ${Object.keys(config.tools).length}`);

      // Create and start server
      const server = new MCPWrapperServer(config, serverOptions);

      // Handle graceful shutdown
      const shutdown = async () => {
        logger.info('Shutting down server...');
        await server.stop();
        process.exit(0);
      };

      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);

      // Start the server
      await server.start();

    } catch (error) {
      logger.error(`Failed to start server: ${error.message}`);
      process.exit(1);
    }
  });

// Error handling for uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error(`Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error(`Unhandled rejection: ${reason}`);
  process.exit(1);
});

program.parse();