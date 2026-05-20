import type { AuditSummary, NormalizedFinding, ProjectSummary } from "./types.js";

type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function projectDisplay(project: JsonObject | undefined): { uuid: string | null; name: string | null; version: string | null } {
  return {
    uuid: asString(project?.["uuid"]),
    name: asString(project?.["name"]),
    version: asString(project?.["version"])
  };
}

export function normalizeProject(project: JsonObject): ProjectSummary {
  const parent = asObject(project["parent"]);
  const tags = Array.isArray(project["tags"])
    ? project["tags"]
        .map((tag) => asString(asObject(tag)?.["name"]))
        .filter((name): name is string => name !== null)
    : [];

  return {
    uuid: String(project["uuid"]),
    group: asString(project["group"]),
    name: String(project["name"]),
    version: asString(project["version"]),
    classifier: asString(project["classifier"]),
    collectionLogic: asString(project["collectionLogic"]),
    active: asBoolean(project["active"]),
    isLatest: asBoolean(project["isLatest"]),
    lastBomImport: typeof project["lastBomImport"] === "number" ? project["lastBomImport"] : null,
    parent: parent
      ? {
          uuid: String(parent["uuid"]),
          name: String(parent["name"]),
          version: asString(parent["version"])
        }
      : null,
    tags
  };
}

export function normalizeFinding(finding: unknown, fallbackProject?: JsonObject): NormalizedFinding {
  const findingObject = asObject(finding) ?? {};
  const component = asObject(findingObject["component"]);
  const vulnerability = asObject(findingObject["vulnerability"]);
  const analysis = asObject(findingObject["analysis"]);
  const project = asObject(component?.["project"]) ?? fallbackProject;

  const normalized: NormalizedFinding = {
    project: projectDisplay(project),
    component: {
      uuid: asString(component?.["uuid"]),
      name: asString(component?.["name"]),
      version: asString(component?.["version"]),
      purl: asString(component?.["purl"])
    },
    vulnerability: {
      uuid: asString(vulnerability?.["uuid"]),
      vulnId: asString(vulnerability?.["vulnId"]) ?? asString(vulnerability?.["vulnIdNormalized"]) ?? asString(vulnerability?.["id"]),
      source: asString(vulnerability?.["source"]),
      severity: asString(vulnerability?.["severity"]),
      title: asString(vulnerability?.["title"])
    },
    analysis: {
      state: asString(analysis?.["analysisState"]),
      justification: asString(analysis?.["analysisJustification"]),
      response: asString(analysis?.["analysisResponse"]),
      details: asString(analysis?.["analysisDetails"]),
      suppressed: asBoolean(analysis?.["isSuppressed"]) ?? asBoolean(analysis?.["suppressed"])
    },
    matrix: asString(findingObject["matrix"])
  };

  if (normalized.component.uuid === null || normalized.vulnerability.uuid === null) {
    return {
      ...normalized,
      raw: findingObject
    };
  }

  return normalized;
}

export function matchesFindingFilters(
  finding: NormalizedFinding,
  filters: {
    readonly analysis_state?: string;
    readonly severity?: string;
  }
): boolean {
  if (filters.analysis_state && finding.analysis.state !== filters.analysis_state) {
    return false;
  }
  if (filters.severity && finding.vulnerability.severity !== filters.severity) {
    return false;
  }
  return true;
}

export function summarizeFindings(findings: readonly NormalizedFinding[]): AuditSummary {
  const bySeverity: Record<string, number> = {};
  const byAnalysisState: Record<string, number> = {};
  const suppressed = {
    true: 0,
    false: 0,
    unknown: 0
  };

  for (const finding of findings) {
    const severity = finding.vulnerability.severity ?? "UNKNOWN";
    bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;

    const state = finding.analysis.state ?? "NOT_SET";
    byAnalysisState[state] = (byAnalysisState[state] ?? 0) + 1;

    if (finding.analysis.suppressed === true) {
      suppressed.true += 1;
    } else if (finding.analysis.suppressed === false) {
      suppressed.false += 1;
    } else {
      suppressed.unknown += 1;
    }
  }

  return {
    totalFindings: findings.length,
    bySeverity,
    byAnalysisState,
    suppressed
  };
}
