import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { DtrackClient } from "./dtrack-client.js";
import {
  AmbiguousMatchError,
  ConfigurationError,
  DtrackHttpError,
  InvalidTargetError,
  NotFoundError,
  ValidationError
} from "./errors.js";
import { matchesFindingFilters, normalizeFinding, normalizeProject, summarizeFindings } from "./normalize.js";
import type { DtrackConfig, FindingFilters, GroupTargetInput, ListProjectsInput, ProjectTargetInput } from "./types.js";

const ANALYSIS_STATES = new Set(["EXPLOITABLE", "IN_TRIAGE", "FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED", "NOT_SET"]);
const ANALYSIS_JUSTIFICATIONS = new Set([
  "CODE_NOT_PRESENT",
  "CODE_NOT_REACHABLE",
  "REQUIRES_CONFIGURATION",
  "REQUIRES_DEPENDENCY",
  "REQUIRES_ENVIRONMENT",
  "PROTECTED_BY_COMPILER",
  "PROTECTED_AT_RUNTIME",
  "PROTECTED_AT_PERIMETER",
  "PROTECTED_BY_MITIGATING_CONTROL",
  "NOT_SET"
]);
const ANALYSIS_RESPONSES = new Set(["CAN_NOT_FIX", "WILL_NOT_FIX", "UPDATE", "ROLLBACK", "WORKAROUND_AVAILABLE", "NOT_SET"]);

function logToolError(toolName: string, error: unknown): void {
  const message = toErrorText(error);
  process.stderr.write(`[${toolName}] ${message}\n`);
}

function formatCause(error: Error, depth = 0): string[] {
  const lines: string[] = [];
  if (depth > 5) {
    return lines;
  }

  const cause = error.cause;
  if (!(cause instanceof Error)) {
    if (cause !== undefined) {
      lines.push(`${"  ".repeat(depth + 1)}Caused by: ${String(cause)}`);
    }
    return lines;
  }

  const indent = "  ".repeat(depth + 1);
  lines.push(`${indent}Caused by: ${cause.stack ?? cause.message}`);
  lines.push(...formatCause(cause, depth + 1));
  return lines;
}

function toErrorText(error: unknown): string {
  if (error instanceof Error) {
    const root = error.stack ?? error.message;
    const causeLines = formatCause(error);
    return causeLines.length > 0 ? `${root}\n${causeLines.join("\n")}` : root;
  }
  return String(error);
}

function asTextResult(payload: unknown): CallToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2)
      }
    ],
    structuredContent: payload as Record<string, unknown>
  };
}

function mapError(error: unknown): never {
  if (
    error instanceof ConfigurationError ||
    error instanceof NotFoundError ||
    error instanceof InvalidTargetError ||
    error instanceof ValidationError
  ) {
    throw new Error(toErrorText(error));
  }

  if (error instanceof AmbiguousMatchError) {
    throw new Error(
      JSON.stringify(
        {
          message: error.message,
          candidates: error.candidates,
          stack: toErrorText(error)
        },
        null,
        2
      )
    );
  }

  if (error instanceof DtrackHttpError) {
    if (error.status === 401) {
      throw new Error(`${toErrorText(error)}\nDependency-Track authentication failed (401)`);
    }
    if (error.status === 403) {
      throw new Error(`${toErrorText(error)}\nDependency-Track permission denied (403)`);
    }
    throw new Error(toErrorText(error));
  }

  throw error instanceof Error ? new Error(toErrorText(error)) : new Error(String(error));
}

const projectFilterSchema = {
  include_suppressed: z.boolean().optional(),
  source: z.string().optional(),
  analysis_state: z.string().optional(),
  severity: z.string().optional()
};

function applyFindingFilters(findings: ReturnType<typeof normalizeFinding>[], filters: FindingFilters) {
  return findings.filter((finding) => matchesFindingFilters(finding, filters));
}

function normalizeEnumInput(value: string | undefined, allowedValues: ReadonlySet<string>, fieldName: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  const normalized = value
    .trim()
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();

  if (!normalized) {
    return undefined;
  }

  if (!allowedValues.has(normalized)) {
    throw new ValidationError(
      `${fieldName} must be one of: ${Array.from(allowedValues).join(", ")}`
    );
  }

  return normalized;
}

export function createServer(config: DtrackConfig, fetchFn: typeof fetch = fetch): McpServer {
  const client = new DtrackClient(config, fetchFn);
  const server = new McpServer({
    name: "dtrack-mcp",
    version: "0.1.0"
  });
  const readOnlyAnnotations = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true
  } as const;
  const writeAnnotations = {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true
  } as const;

  server.registerTool(
    "get_vulnerability_details",
    {
      description: "Fetch canonical vulnerability details for a vulnerability returned by project findings.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        vulnerability_uuid: z.string().uuid().optional(),
        vulnerability_source: z.string().min(1).optional(),
        vulnerability_id: z.string().min(1).optional(),
        component_uuid: z.string().uuid().optional()
      }
    },
    async (input: {
      vulnerability_uuid?: string;
      vulnerability_source?: string;
      vulnerability_id?: string;
      component_uuid?: string;
    }) => {
      try {
        let vulnerability: Record<string, unknown>;

        if (input.vulnerability_source && input.vulnerability_id) {
          vulnerability = await client.getVulnerabilityBySourceAndId(input.vulnerability_source, input.vulnerability_id);
        } else if (input.vulnerability_uuid) {
          vulnerability = await client.getVulnerabilityByUuid(input.vulnerability_uuid);
        } else {
          throw new ValidationError(
            "Provide vulnerability_source with vulnerability_id, or provide vulnerability_uuid"
          );
        }

        return asTextResult({
          lookup: {
            vulnerability_uuid: input.vulnerability_uuid ?? null,
            vulnerability_source: input.vulnerability_source ?? null,
            vulnerability_id: input.vulnerability_id ?? null,
            component_uuid: input.component_uuid ?? null
          },
          vulnerability
        });
      } catch (error) {
        logToolError("get_vulnerability_details", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "list_projects",
    {
      description: "List Dependency-Track projects with optional name and hierarchy filters.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        project_name: z.string().min(1).optional(),
        include_inactive: z.boolean().optional(),
        only_root: z.boolean().optional()
      }
    },
    async (input: ListProjectsInput) => {
      try {
        const projects = await client.listProjects({
          name: input.project_name,
          includeInactive: input.include_inactive,
          onlyRoot: input.only_root
        });
        return asTextResult({
          projects: projects.map((project) => normalizeProject(project))
        });
      } catch (error) {
        logToolError("list_projects", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "get_project",
    {
      description: "Get a Dependency-Track project by name and optional version.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        project_name: z.string().min(1),
        project_version: z.string().min(1).optional()
      }
    },
    async (input: ProjectTargetInput) => {
      try {
        const project = await client.resolveProjectByName(input.project_name, input.project_version);
        const versions = await client.listProjectVersionsByName(input.project_name);
        return asTextResult({
          project: normalizeProject(project),
          versions: versions.map((item) => normalizeProject(item))
        });
      } catch (error) {
        logToolError("get_project", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "get_group",
    {
      description: "Get a Dependency-Track collection project by name and its direct children.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        group_name: z.string().min(1),
        include_inactive_children: z.boolean().optional()
      }
    },
    async (input: GroupTargetInput & { include_inactive_children?: boolean }) => {
      try {
        const group = await client.resolveCollectionProjectByName(input.group_name);
        const children = await client.getProjectChildren(String(group["uuid"]), input.include_inactive_children);
        return asTextResult({
          group: normalizeProject(group),
          children: children.map((child) => normalizeProject(child))
        });
      } catch (error) {
        logToolError("get_group", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "list_project_findings",
    {
      description: "List normalized findings for a Dependency-Track project.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        project_name: z.string().min(1),
        project_version: z.string().min(1).optional(),
        ...projectFilterSchema
      }
    },
    async (input: ProjectTargetInput & FindingFilters) => {
      try {
        const project = await client.resolveProjectByName(input.project_name, input.project_version);
        const findings = await client.getProjectFindings(String(project["uuid"]), {
          includeSuppressed: input.include_suppressed,
          source: input.source
        });
        const normalized = applyFindingFilters(
          findings.map((finding) => normalizeFinding(finding, project)),
          input
        );

        return asTextResult({
          project: normalizeProject(project),
          findings: normalized
        });
      } catch (error) {
        logToolError("list_project_findings", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "audit_project_vulnerabilities",
    {
      description: "Audit project findings with summary counts and optional filtering.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        project_name: z.string().min(1),
        project_version: z.string().min(1).optional(),
        ...projectFilterSchema
      }
    },
    async (input: ProjectTargetInput & FindingFilters) => {
      try {
        const project = await client.resolveProjectByName(input.project_name, input.project_version);
        const findings = await client.getProjectFindings(String(project["uuid"]), {
          includeSuppressed: input.include_suppressed,
          source: input.source
        });
        const normalized = applyFindingFilters(
          findings.map((finding) => normalizeFinding(finding, project)),
          input
        );

        return asTextResult({
          project: normalizeProject(project),
          summary: summarizeFindings(normalized),
          findings: normalized
        });
      } catch (error) {
        logToolError("audit_project_vulnerabilities", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "audit_group_vulnerabilities",
    {
      description: "Audit a collection project's child projects and aggregate their findings.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        group_name: z.string().min(1),
        include_inactive_children: z.boolean().optional(),
        ...projectFilterSchema
      }
    },
    async (input: GroupTargetInput & FindingFilters & { include_inactive_children?: boolean }) => {
      try {
        const group = await client.resolveCollectionProjectByName(input.group_name);
        const children = await client.getProjectChildren(String(group["uuid"]), input.include_inactive_children);

        const perProject = await Promise.all(
          children.map(async (child) => {
            const findings = await client.getProjectFindings(String(child["uuid"]), {
              includeSuppressed: input.include_suppressed,
              source: input.source
            });
            const normalized = applyFindingFilters(
              findings.map((finding) => normalizeFinding(finding, child)),
              input
            );
            return {
              project: normalizeProject(child),
              summary: summarizeFindings(normalized),
              findings: normalized
            };
          })
        );

        return asTextResult({
          group: normalizeProject(group),
          summary: summarizeFindings(perProject.flatMap((item) => item.findings)),
          projects: perProject.map(({ project, summary }) => ({ project, summary })),
          findings: perProject.flatMap((item) => item.findings)
        });
      } catch (error) {
        logToolError("audit_group_vulnerabilities", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "get_vulnerability_analysis",
    {
      description: "Fetch the analysis trail for a component and vulnerability in a project.",
      annotations: readOnlyAnnotations,
      inputSchema: {
        project_name: z.string().min(1),
        project_version: z.string().min(1).optional(),
        component_uuid: z.string().uuid(),
        vulnerability_uuid: z.string().uuid()
      }
    },
    async (input: ProjectTargetInput & { component_uuid: string; vulnerability_uuid: string }) => {
      try {
        const project = await client.resolveProjectByName(input.project_name, input.project_version);
        const analysis = await client.getAnalysis(String(project["uuid"]), input.component_uuid, input.vulnerability_uuid);
        return asTextResult({
          project: normalizeProject(project),
          analysis
        });
      } catch (error) {
        logToolError("get_vulnerability_analysis", error);
        mapError(error);
      }
    }
  );

  server.registerTool(
    "update_vulnerability_analysis",
    {
      description: "Update a vulnerability analysis decision through Dependency-Track's analysis endpoint.",
      annotations: writeAnnotations,
      inputSchema: {
        project_name: z.string().min(1),
        project_version: z.string().min(1).optional(),
        component_uuid: z.string().uuid(),
        vulnerability_uuid: z.string().uuid(),
        analysis_state: z.string().optional(),
        analysis_justification: z.string().optional(),
        analysis_response: z.string().optional(),
        analysis_details: z.string().optional(),
        comment: z.string().optional(),
        suppressed: z.boolean().optional()
      }
    },
    async (
      input: ProjectTargetInput & {
        component_uuid: string;
        vulnerability_uuid: string;
        analysis_state?: string;
        analysis_justification?: string;
        analysis_response?: string;
        analysis_details?: string;
        comment?: string;
        suppressed?: boolean;
      }
    ) => {
      try {
        const project = await client.resolveProjectByName(input.project_name, input.project_version);
        const analysis = await client.updateAnalysis({
          project: String(project["uuid"]),
          component: input.component_uuid,
          vulnerability: input.vulnerability_uuid,
          analysisState: normalizeEnumInput(input.analysis_state, ANALYSIS_STATES, "analysis_state"),
          analysisJustification: normalizeEnumInput(
            input.analysis_justification,
            ANALYSIS_JUSTIFICATIONS,
            "analysis_justification"
          ),
          analysisResponse: normalizeEnumInput(input.analysis_response, ANALYSIS_RESPONSES, "analysis_response"),
          analysisDetails: input.analysis_details,
          comment: input.comment,
          suppressed: input.suppressed
        });

        return asTextResult({
          project: normalizeProject(project),
          analysis
        });
      } catch (error) {
        logToolError("update_vulnerability_analysis", error);
        mapError(error);
      }
    }
  );

  return server;
}
