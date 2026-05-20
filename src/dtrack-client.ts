import {
  AmbiguousMatchError,
  DtrackHttpError,
  InvalidTargetError,
  NotFoundError,
  ValidationError
} from "./errors.js";
import { normalizeProject } from "./normalize.js";
import type { DtrackConfig } from "./types.js";

type JsonObject = Record<string, unknown>;

interface RequestOptions {
  readonly query?: Record<string, string | boolean | undefined>;
  readonly method?: "GET" | "PUT";
  readonly body?: unknown;
}

export class DtrackClient {
  readonly #config: DtrackConfig;
  readonly #fetchFn: typeof fetch;

  constructor(config: DtrackConfig, fetchFn: typeof fetch = fetch) {
    this.#config = config;
    this.#fetchFn = fetchFn;
  }

  async getLatestProjectByName(name: string): Promise<JsonObject> {
    return this.#requestJson<JsonObject>(`/v1/project/latest/${encodeURIComponent(name)}`);
  }

  async getProjectByNameAndVersion(name: string, version: string): Promise<JsonObject> {
    return this.#requestJson<JsonObject>("/v1/project/lookup", {
      query: {
        name,
        version
      }
    });
  }

  async searchProjectsByName(name: string, onlyRoot = false): Promise<JsonObject[]> {
    return this.#requestJson<JsonObject[]>("/v1/project", {
      query: {
        name,
        onlyRoot
      }
    });
  }

  async listProjects(options: { name?: string; includeInactive?: boolean; onlyRoot?: boolean } = {}): Promise<JsonObject[]> {
    const projects: JsonObject[] = [];
    let offset = 0;
    const limit = 100;
    const nameFilter = normalizeNameFilter(options.name);

    while (true) {
      const batch = await this.#requestJson<JsonObject[]>("/v1/project", {
        query: {
          offset: String(offset),
          limit: String(limit),
          excludeInactive: options.includeInactive ? undefined : true,
          onlyRoot: options.onlyRoot
        }
      });

      projects.push(...batch);
      if (batch.length < limit) {
        return nameFilter
          ? projects.filter((project) => matchesProjectName(project, nameFilter))
          : projects;
      }
      offset += batch.length;
    }
  }

  async listProjectVersionsByName(name: string): Promise<JsonObject[]> {
    const projects = await this.listProjects({
      name,
      includeInactive: true
    });

    return projects.filter((project) => project["name"] === name);
  }

  async getProjectChildren(projectUuid: string, includeInactiveChildren = false): Promise<JsonObject[]> {
    const children: JsonObject[] = [];
    let offset = 0;
    const limit = 100;

    while (true) {
      const batch = await this.#requestJson<JsonObject[]>(`/v1/project/${encodeURIComponent(projectUuid)}/children`, {
        query: {
          offset: String(offset),
          limit: String(limit),
          excludeInactive: !includeInactiveChildren
        }
      });

      children.push(...batch);
      if (batch.length < limit) {
        return children;
      }
      offset += batch.length;
    }
  }

  async getProjectFindings(projectUuid: string, options: { includeSuppressed?: boolean; source?: string } = {}): Promise<unknown[]> {
    return this.#requestJson<unknown[]>(`/v1/finding/project/${encodeURIComponent(projectUuid)}`, {
      query: {
        suppressed: options.includeSuppressed,
        source: options.source
      }
    });
  }

  async getVulnerabilityByUuid(vulnerabilityUuid: string): Promise<JsonObject> {
    return this.#requestJson<JsonObject>(`/v1/vulnerability/${encodeURIComponent(vulnerabilityUuid)}`);
  }

  async getVulnerabilityBySourceAndId(source: string, vulnId: string): Promise<JsonObject> {
    return this.#requestJson<JsonObject>(
      `/v1/vulnerability/source/${encodeURIComponent(source)}/vuln/${encodeURIComponent(vulnId)}`
    );
  }

  async getAnalysis(projectUuid: string | undefined, componentUuid: string, vulnerabilityUuid: string): Promise<JsonObject> {
    return this.#requestJson<JsonObject>("/v1/analysis", {
      query: {
        project: projectUuid,
        component: componentUuid,
        vulnerability: vulnerabilityUuid
      }
    });
  }

  async updateAnalysis(input: {
    readonly project?: string;
    readonly component: string;
    readonly vulnerability: string;
    readonly analysisState?: string;
    readonly analysisJustification?: string;
    readonly analysisResponse?: string;
    readonly analysisDetails?: string;
    readonly comment?: string;
    readonly suppressed?: boolean;
  }): Promise<JsonObject> {
    if (!input.component || !input.vulnerability) {
      throw new ValidationError("component and vulnerability UUIDs are required");
    }

    return this.#requestJson<JsonObject>("/v1/analysis", {
      method: "PUT",
      body: {
        project: input.project,
        component: input.component,
        vulnerability: input.vulnerability,
        analysisState: input.analysisState,
        analysisJustification: input.analysisJustification,
        analysisResponse: input.analysisResponse,
        analysisDetails: input.analysisDetails,
        comment: input.comment,
        suppressed: input.suppressed
      }
    });
  }

  async resolveProjectByName(name: string, version?: string): Promise<JsonObject> {
    if (version) {
      return this.getProjectByNameAndVersion(name, version);
    }

    try {
      return await this.getLatestProjectByName(name);
    } catch (error) {
      if (!(error instanceof NotFoundError)) {
        throw error;
      }
    }

    const candidates = await this.searchProjectsByName(name, false);
    const exactMatches = candidates.filter((project) => project["name"] === name);
    if (exactMatches.length === 1) {
      return exactMatches[0] as JsonObject;
    }
    if (exactMatches.length > 1) {
      throw new AmbiguousMatchError(
        `Multiple projects named "${name}" matched. Provide project_version.`,
        exactMatches.map((candidate) => normalizeProject(candidate) as unknown as Record<string, unknown>)
      );
    }

    throw new NotFoundError(`Project "${name}" was not found`);
  }

  async resolveCollectionProjectByName(name: string): Promise<JsonObject> {
    const candidates = await this.searchProjectsByName(name, false);
    const exactCollectionProjects = candidates.filter(
      (project) => project["name"] === name && project["collectionLogic"] && project["collectionLogic"] !== "NONE"
    );

    if (exactCollectionProjects.length === 1) {
      return exactCollectionProjects[0] as JsonObject;
    }
    if (exactCollectionProjects.length > 1) {
      throw new AmbiguousMatchError(
        `Multiple collection projects named "${name}" matched.`,
        exactCollectionProjects.map((candidate) => normalizeProject(candidate) as unknown as Record<string, unknown>)
      );
    }

    const exactNonCollectionProjects = candidates.filter((project) => project["name"] === name);
    if (exactNonCollectionProjects.length > 0) {
      throw new InvalidTargetError(`Project "${name}" exists but is not a collection project`);
    }

    throw new NotFoundError(`Collection project "${name}" was not found`);
  }

  async #requestJson<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const headers = new Headers({
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "dtrack-mcp/0.1.0"
    });
    if (this.#config.auth.type === "apiKey") {
      headers.set("X-Api-Key", this.#config.auth.value);
    } else {
      headers.set("Authorization", `Bearer ${this.#config.auth.value}`);
    }

    const url = new URL(`${this.#config.baseUrl}${path}`);
    for (const [key, value] of Object.entries(options.query ?? {})) {
      if (value !== undefined) {
        url.searchParams.set(key, String(value));
      }
    }

    const timeout = AbortSignal.timeout(this.#config.timeoutMs);
    const response = await this.#fetchFn(url, {
      method: options.method ?? "GET",
      headers,
      body: options.body ? JSON.stringify(stripUndefined(options.body)) : undefined,
      signal: timeout
    });

    if (!response.ok) {
      const details = await safeReadText(response);
      if (response.status === 404) {
        throw new NotFoundError(details || `Resource ${path} was not found`);
      }
      throw new DtrackHttpError(response.status, details || response.statusText);
    }

    return (await response.json()) as T;
  }
}

function normalizeNameFilter(value: string | undefined): string | undefined {
  const normalized = value?.trim().toLocaleLowerCase();
  return normalized ? normalized : undefined;
}

function matchesProjectName(project: JsonObject, nameFilter: string): boolean {
  const name = project["name"];
  return typeof name === "string" && name.toLocaleLowerCase().includes(nameFilter);
}

async function safeReadText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return "";
  }
}

function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stripUndefined);
  }
  if (typeof value === "object" && value !== null) {
    const next: Record<string, unknown> = {};
    for (const [key, current] of Object.entries(value)) {
      if (current !== undefined) {
        next[key] = stripUndefined(current);
      }
    }
    return next;
  }
  return value;
}
