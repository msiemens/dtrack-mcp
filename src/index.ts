#!/usr/bin/env node

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig, parseCliArgs } from "./config.js";
import { createServer } from "./server.js";

const HELP_TEXT = `dtrack-mcp

Dependency-Track MCP server over stdio.

Usage:
  dtrack-mcp [options]

Options:
  -h, --help                 Show this help text and exit
  --base-url <url>           Dependency-Track base API URL
  --api-key <key>            Dependency-Track API key
  --bearer-token <token>     Dependency-Track bearer token
  --timeout-ms <ms>          Request timeout in milliseconds
  --insecure-tls <bool>      Disable TLS certificate verification for requests

Environment:
  DTRACK_BASE_URL
  DTRACK_API_KEY
  DTRACK_BEARER_TOKEN
  DTRACK_TIMEOUT_MS
  DTRACK_INSECURE_TLS
`;

async function main(): Promise<void> {
  const cli = parseCliArgs(process.argv.slice(2));
  if (cli.help) {
    process.stdout.write(`${HELP_TEXT}\n`);
    return;
  }

  const config = loadConfig(process.argv.slice(2));
  if (config.insecureTls) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }
  const server = createServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
