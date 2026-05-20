export interface DtrackConfig {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  readonly insecureTls: boolean;
  readonly auth:
    | {
        readonly type: "apiKey";
        readonly value: string;
      }
    | {
        readonly type: "bearer";
        readonly value: string;
      };
}

export interface ProjectTargetInput {
  readonly project_name: string;
  readonly project_version?: string;
}

export interface GroupTargetInput {
  readonly group_name: string;
}

export interface ListProjectsInput {
  readonly project_name?: string;
  readonly include_inactive?: boolean;
  readonly only_root?: boolean;
}

export interface FindingFilters {
  readonly include_suppressed?: boolean;
  readonly source?: string;
  readonly analysis_state?: string;
  readonly severity?: string;
}

export interface ProjectSummary {
  readonly uuid: string;
  readonly group: string | null;
  readonly name: string;
  readonly version: string | null;
  readonly classifier: string | null;
  readonly collectionLogic: string | null;
  readonly active: boolean | null;
  readonly isLatest: boolean | null;
  readonly lastBomImport: number | null;
  readonly parent: {
    readonly uuid: string;
    readonly name: string;
    readonly version: string | null;
  } | null;
  readonly tags: readonly string[];
}

export interface NormalizedFinding {
  readonly project: {
    readonly uuid: string | null;
    readonly name: string | null;
    readonly version: string | null;
  };
  readonly component: {
    readonly uuid: string | null;
    readonly name: string | null;
    readonly version: string | null;
    readonly purl: string | null;
  };
  readonly vulnerability: {
    readonly uuid: string | null;
    readonly vulnId: string | null;
    readonly source: string | null;
    readonly severity: string | null;
    readonly title: string | null;
  };
  readonly analysis: {
    readonly state: string | null;
    readonly justification: string | null;
    readonly response: string | null;
    readonly details: string | null;
    readonly suppressed: boolean | null;
  };
  readonly matrix: string | null;
  readonly raw?: Record<string, unknown>;
}

export interface AuditSummary {
  readonly totalFindings: number;
  readonly bySeverity: Record<string, number>;
  readonly byAnalysisState: Record<string, number>;
  readonly suppressed: {
    readonly true: number;
    readonly false: number;
    readonly unknown: number;
  };
}
