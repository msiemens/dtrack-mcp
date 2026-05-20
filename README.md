# dtrack-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[OWASP Dependency-Track](https://dependencytrack.org/). It exposes a small set
of read and audit tools over stdio so MCP-capable clients (Claude Desktop,
Claude Code, etc.) can query projects, findings, and vulnerability analyses.

## Tools

| Tool | Description |
| ---- | ----------- |
| `list_projects` | List projects with optional name / hierarchy filters. |
| `get_project` | Look up a project by name (and optional version) and list its versions. |
| `get_group` | Resolve a collection project and list its direct children. |
| `list_project_findings` | Normalized findings for a project, with filter options. |
| `audit_project_vulnerabilities` | Findings plus summary counts for a single project. |
| `audit_group_vulnerabilities` | Aggregate findings across a collection project's children. |
| `get_vulnerability_analysis` | Fetch the analysis trail for a component/vulnerability pair. |
| `update_vulnerability_analysis` | Update the analysis decision for a component/vulnerability pair. |
| `get_vulnerability_details` | Fetch canonical vulnerability details by UUID or source + ID. |

## Configuration

Configuration can be supplied through environment variables or CLI flags. CLI
flags take precedence.

| Variable | Flag | Description |
| -------- | ---- | ----------- |
| `DTRACK_BASE_URL` | `--base-url <url>` | Dependency-Track API base URL (required). |
| `DTRACK_API_KEY` | `--api-key <key>` | API key. Mutually exclusive with bearer token. |
| `DTRACK_BEARER_TOKEN` | `--bearer-token <token>` | OAuth/JWT bearer token. Mutually exclusive with API key. |
| `DTRACK_TIMEOUT_MS` | `--timeout-ms <ms>` | Request timeout in milliseconds (default `30000`). |
| `DTRACK_INSECURE_TLS` | `--insecure-tls <bool>` | Disable TLS verification (for self-signed certs). |

## Install

From a clone:

```sh
pnpm install
pnpm build
```

The built entry point is `dist/index.js` and is registered as the `dtrack-mcp`
bin.

## Usage with an MCP client

Example client configuration (Claude Desktop / Claude Code style):

```json
{
  "mcpServers": {
    "dtrack": {
      "command": "npx",
      "args": ["-y", "dtrack-mcp"],
      "env": {
        "DTRACK_BASE_URL": "https://dtrack.example.com/api",
        "DTRACK_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

To run straight from a GitHub clone without publishing, point `npx` at the
repository:

```json
{
  "mcpServers": {
    "dtrack": {
      "command": "npx",
      "args": ["-y", "github:msiemens/dtrack-mcp"],
      "env": {
        "DTRACK_BASE_URL": "https://dtrack.example.com/api",
        "DTRACK_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

## Development

```sh
pnpm install
pnpm test
pnpm build
```

`openapi.json` is the upstream OWASP Dependency-Track OpenAPI specification,
checked in as a reference for the client code.

## License

[MIT](LICENSE)
