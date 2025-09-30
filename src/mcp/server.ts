import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { MCPConfig, ServerOptions } from '../types/config.js';
import { createMCPToolFromDefinition, createToolExecutor } from './tools.js';
import { createContextLogger } from '../utils/logger.js';

const logger = createContextLogger('server');

export class MCPWrapperServer {
  private server: Server;
  private config: MCPConfig;
  private options: ServerOptions;

  constructor(config: MCPConfig, options: ServerOptions) {
    this.config = config;
    this.options = options;

    this.server = new Server(
      {
        name: options.name || 'mcp-wrapper',
        version: options.version || '1.0.0'
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.setupHandlers();
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools = Object.entries(this.config.tools).map(([name, definition]) =>
        createMCPToolFromDefinition(name, definition)
      );

      logger.info(`Returning ${tools.length} tools`);
      return { tools };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      logger.info(`Executing tool: ${name}`);

      // Find tool by name (either config key or display name)
      let definition = this.config.tools[name];

      if (!definition) {
        // Look for tool by display name
        const foundEntry = Object.entries(this.config.tools).find(([, tool]) =>
          tool.name === name
        );
        if (foundEntry) {
          definition = foundEntry[1];
        }
      }

      if (!definition) {
        throw new Error(`Tool '${name}' not found`);
      }
      const executor = createToolExecutor(definition);
      const result = await executor(args || {});

      if (result.success) {
        return {
          content: [
            {
              type: 'text' as const,
              text: result.stdout || 'Command executed successfully'
            }
          ]
        };
      } else {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error: ${result.stderr || 'Command failed'}`
            }
          ],
          isError: true
        };
      }
    });
  }

  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    logger.info('MCP server started with stdio transport');
  }

  async stop(): Promise<void> {
    await this.server.close();
    logger.info('MCP server stopped');
  }
}