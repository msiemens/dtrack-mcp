import { ConfigurationError } from "./errors.js";
import type { DtrackConfig } from "./types.js";

interface CliArgs {
  readonly baseUrl?: string;
  readonly apiKey?: string;
  readonly bearerToken?: string;
  readonly timeoutMs?: number;
  readonly help?: boolean;
  readonly insecureTls?: boolean;
}

function parseBooleanFlag(value: string, flagName: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["false", "0", "no", "off"].includes(normalized)) {
    return false;
  }
  throw new ConfigurationError(`Invalid boolean value for ${flagName}: ${value}`);
}

export function parseCliArgs(argv: readonly string[]): CliArgs {
  const args: Record<string, string> = {};
  let help = false;

  for (let index = 0; index < argv.length; ) {
    const key = argv[index];
    if (!key?.startsWith("--")) {
      if (key === "-h") {
        help = true;
        index += 1;
        continue;
      }
      throw new ConfigurationError(`Unexpected argument: ${String(key)}`);
    }
    if (key === "--help") {
      help = true;
      index += 1;
      continue;
    }

    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new ConfigurationError(`Missing value for ${key}`);
    }
    args[key.slice(2)] = value;
    index += 2;
  }

  return {
    baseUrl: args["base-url"],
    apiKey: args["api-key"],
    bearerToken: args["bearer-token"],
    timeoutMs: args["timeout-ms"] ? Number.parseInt(args["timeout-ms"], 10) : undefined,
    help,
    insecureTls: args["insecure-tls"] ? parseBooleanFlag(args["insecure-tls"], "--insecure-tls") : undefined
  };
}

export function loadConfig(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): DtrackConfig {
  const cli = parseCliArgs(argv);
  const baseUrl = (cli.baseUrl ?? env.DTRACK_BASE_URL ?? "").trim().replace(/\/+$/, "");
  if (!baseUrl) {
    throw new ConfigurationError("Dependency-Track base URL is required via DTRACK_BASE_URL or --base-url");
  }

  const apiKey = (cli.apiKey ?? env.DTRACK_API_KEY ?? "").trim();
  const bearerToken = (cli.bearerToken ?? env.DTRACK_BEARER_TOKEN ?? "").trim();
  if (!apiKey && !bearerToken) {
    throw new ConfigurationError("Provide DTRACK_API_KEY or DTRACK_BEARER_TOKEN");
  }
  if (apiKey && bearerToken) {
    throw new ConfigurationError("Configure exactly one auth mode: API key or bearer token");
  }

  const timeoutMs = cli.timeoutMs ?? (env.DTRACK_TIMEOUT_MS ? Number.parseInt(env.DTRACK_TIMEOUT_MS, 10) : 30_000);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ConfigurationError("Timeout must be a positive integer number of milliseconds");
  }

  const insecureTls =
    cli.insecureTls ??
    (env.DTRACK_INSECURE_TLS ? parseBooleanFlag(env.DTRACK_INSECURE_TLS, "DTRACK_INSECURE_TLS") : false);

  return {
    baseUrl,
    timeoutMs,
    insecureTls,
    auth: apiKey
      ? {
          type: "apiKey",
          value: apiKey
        }
      : {
          type: "bearer",
          value: bearerToken
        }
  };
}
