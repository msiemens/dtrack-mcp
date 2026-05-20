import assert from "node:assert/strict";
import test from "node:test";
import { DtrackClient } from "../src/dtrack-client.js";
import { AmbiguousMatchError, InvalidTargetError, NotFoundError } from "../src/errors.js";
import { normalizeFinding, summarizeFindings } from "../src/normalize.js";
import { createServer } from "../src/server.js";
import type { DtrackConfig } from "../src/types.js";

const config: DtrackConfig = {
  baseUrl: "https://dtrack.example/api",
  timeoutMs: 5_000,
  insecureTls: false,
  auth: {
    type: "apiKey",
    value: "secret"
  }
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

test("resolveProjectByName falls back to search and raises ambiguity", async () => {
  const client = new DtrackClient(config, async (input) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/v1/project/latest/demo")) {
      return jsonResponse(404, { message: "not found" });
    }
    if (url.pathname.endsWith("/v1/project")) {
      return jsonResponse(200, [
        { uuid: "1", name: "demo", version: "1.0.0", collectionLogic: "NONE" },
        { uuid: "2", name: "demo", version: "2.0.0", collectionLogic: "NONE" }
      ]);
    }
    throw new Error(`Unexpected request: ${url.pathname}`);
  });

  await assert.rejects(() => client.resolveProjectByName("demo"), AmbiguousMatchError);
});

test("resolveCollectionProjectByName rejects non-collection projects", async () => {
  const client = new DtrackClient(config, async () => {
    return jsonResponse(200, [{ uuid: "1", name: "demo", version: "1.0.0", collectionLogic: "NONE" }]);
  });

  await assert.rejects(() => client.resolveCollectionProjectByName("demo"), InvalidTargetError);
});

test("resolveProjectByName throws not found when no project matches", async () => {
  const client = new DtrackClient(config, async (input) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/v1/project/latest/missing")) {
      return jsonResponse(404, { message: "not found" });
    }
    return jsonResponse(200, []);
  });

  await assert.rejects(() => client.resolveProjectByName("missing"), NotFoundError);
});

test("updateAnalysis sends only defined fields", async () => {
  let capturedBody = "";
  const client = new DtrackClient(config, async (_input, init) => {
    capturedBody = String(init?.body ?? "");
    return jsonResponse(200, { analysisState: "IN_TRIAGE" });
  });

  await client.updateAnalysis({
    project: "project-uuid",
    component: "component-uuid",
    vulnerability: "vulnerability-uuid",
    analysisState: "IN_TRIAGE",
    comment: "Investigating"
  });

  assert.deepEqual(JSON.parse(capturedBody), {
    project: "project-uuid",
    component: "component-uuid",
    vulnerability: "vulnerability-uuid",
    analysisState: "IN_TRIAGE",
    comment: "Investigating"
  });
});

test("listProjects paginates and excludes inactive projects by default", async () => {
  const requests: URL[] = [];
  const client = new DtrackClient(config, async (input) => {
    const url = new URL(String(input));
    requests.push(url);

    const offset = Number(url.searchParams.get("offset") ?? "0");
    const limit = Number(url.searchParams.get("limit") ?? "100");
    const total = 101;
    const remaining = Math.max(total - offset, 0);
    const batchSize = Math.min(limit, remaining);

    return jsonResponse(
      200,
      Array.from({ length: batchSize }, (_, index) => ({
        uuid: `project-${offset + index}`,
        name: `demo-${offset + index}`,
        version: "1.0.0",
        collectionLogic: "NONE"
      }))
    );
  });

  const projects = await client.listProjects();

  assert.equal(projects.length, 101);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].searchParams.get("excludeInactive"), "true");
  assert.equal(requests[0].searchParams.get("offset"), "0");
  assert.equal(requests[0].searchParams.get("limit"), "100");
  assert.equal(requests[1].searchParams.get("offset"), "100");
});

test("listProjects forwards optional filters", async () => {
  let request: URL | undefined;
  const client = new DtrackClient(config, async (input) => {
    request = new URL(String(input));
    return jsonResponse(200, []);
  });

  await client.listProjects({
    name: "demo",
    includeInactive: true,
    onlyRoot: true
  });

  assert.ok(request);
  assert.equal(request.searchParams.has("name"), false);
  assert.equal(request.searchParams.get("onlyRoot"), "true");
  assert.equal(request.searchParams.has("excludeInactive"), false);
});

test("listProjects filters project names by partial case-insensitive match", async () => {
  const client = new DtrackClient(config, async () => {
    return jsonResponse(200, [
      { uuid: "1", name: "Demo API", version: "1.0.0", collectionLogic: "NONE" },
      { uuid: "2", name: "internal-demo-worker", version: "1.0.0", collectionLogic: "NONE" },
      { uuid: "3", name: "Payments", version: "1.0.0", collectionLogic: "NONE" }
    ]);
  });

  const projects = await client.listProjects({
    name: "dEmO"
  });

  assert.deepEqual(
    projects.map((project) => project["name"]),
    ["Demo API", "internal-demo-worker"]
  );
});

test("listProjectVersionsByName returns exact-name versions and includes inactive", async () => {
  let request: URL | undefined;
  const client = new DtrackClient(config, async (input) => {
    request = new URL(String(input));
    return jsonResponse(200, [
      { uuid: "1", name: "demo", version: "1.0.0", active: true, collectionLogic: "NONE" },
      { uuid: "2", name: "demo", version: "2.0.0", active: false, collectionLogic: "NONE" },
      { uuid: "3", name: "demo-other", version: "1.0.0", active: true, collectionLogic: "NONE" }
    ]);
  });

  const projects = await client.listProjectVersionsByName("demo");

  assert.ok(request);
  assert.equal(request.searchParams.has("name"), false);
  assert.equal(request.searchParams.has("excludeInactive"), false);
  assert.deepEqual(
    projects.map((project) => project["version"]),
    ["1.0.0", "2.0.0"]
  );
});

test("getVulnerabilityBySourceAndId calls view-portfolio endpoint", async () => {
  let request: URL | undefined;
  const client = new DtrackClient(config, async (input) => {
    request = new URL(String(input));
    return jsonResponse(200, { uuid: "vuln-uuid", source: "NVD", vulnId: "CVE-2025-0001" });
  });

  const vulnerability = await client.getVulnerabilityBySourceAndId("NVD", "CVE-2025-0001");

  assert.ok(request);
  assert.equal(request.pathname, "/api/v1/vulnerability/source/NVD/vuln/CVE-2025-0001");
  assert.equal(vulnerability["vulnId"], "CVE-2025-0001");
});

test("getVulnerabilityByUuid calls uuid endpoint", async () => {
  let request: URL | undefined;
  const client = new DtrackClient(config, async (input) => {
    request = new URL(String(input));
    return jsonResponse(200, { uuid: "123e4567-e89b-12d3-a456-426614174000" });
  });

  const vulnerability = await client.getVulnerabilityByUuid("123e4567-e89b-12d3-a456-426614174000");

  assert.ok(request);
  assert.equal(request.pathname, "/api/v1/vulnerability/123e4567-e89b-12d3-a456-426614174000");
  assert.equal(vulnerability["uuid"], "123e4567-e89b-12d3-a456-426614174000");
});

test("update_vulnerability_analysis normalizes friendly enum inputs", async () => {
  let capturedBody = "";
  const server = createServer(config, async (input, init) => {
    const url = new URL(String(input));

    if (url.pathname.endsWith("/v1/project/lookup")) {
      return jsonResponse(200, { uuid: "project-uuid", name: "demo", version: "1.0.0", collectionLogic: "NONE" });
    }

    if (url.pathname.endsWith("/v1/analysis")) {
      capturedBody = String(init?.body ?? "");
      return jsonResponse(200, { analysisState: "NOT_AFFECTED" });
    }

    throw new Error(`Unexpected request: ${url.pathname}`);
  });

  const tool = (server as unknown as { _registeredTools: Record<string, { handler: (input: unknown) => Promise<unknown> }> })
    ._registeredTools["update_vulnerability_analysis"];

  await tool.handler({
    project_name: "demo",
    project_version: "1.0.0",
    component_uuid: "123e4567-e89b-12d3-a456-426614174001",
    vulnerability_uuid: "123e4567-e89b-12d3-a456-426614174002",
    analysis_state: "not_affected",
    analysis_justification: "code_not_present",
    analysis_response: "can_not_fix"
  });

  assert.deepEqual(JSON.parse(capturedBody), {
    project: "project-uuid",
    component: "123e4567-e89b-12d3-a456-426614174001",
    vulnerability: "123e4567-e89b-12d3-a456-426614174002",
    analysisState: "NOT_AFFECTED",
    analysisJustification: "CODE_NOT_PRESENT",
    analysisResponse: "CAN_NOT_FIX"
  });
});

test("normalizeFinding keeps raw payload when key UUIDs are missing", () => {
  const normalized = normalizeFinding({
    component: {
      name: "lib-a"
    },
    vulnerability: {
      vulnId: "CVE-2025-0001",
      severity: "HIGH"
    },
    analysis: {
      analysisState: "IN_TRIAGE"
    }
  });

  assert.equal(normalized.vulnerability.vulnId, "CVE-2025-0001");
  assert.ok(normalized.raw);
});

test("summarizeFindings counts severity, state, and suppression", () => {
  const summary = summarizeFindings([
    {
      project: { uuid: "p1", name: "a", version: "1" },
      component: { uuid: "c1", name: "lib-a", version: null, purl: null },
      vulnerability: { uuid: "v1", vulnId: "CVE-1", source: "NVD", severity: "HIGH", title: null },
      analysis: { state: "IN_TRIAGE", justification: null, response: null, details: null, suppressed: false },
      matrix: null
    },
    {
      project: { uuid: "p1", name: "a", version: "1" },
      component: { uuid: "c2", name: "lib-b", version: null, purl: null },
      vulnerability: { uuid: "v2", vulnId: "CVE-2", source: "NVD", severity: "HIGH", title: null },
      analysis: { state: null, justification: null, response: null, details: null, suppressed: true },
      matrix: null
    }
  ]);

  assert.equal(summary.totalFindings, 2);
  assert.equal(summary.bySeverity.HIGH, 2);
  assert.equal(summary.byAnalysisState.IN_TRIAGE, 1);
  assert.equal(summary.byAnalysisState.NOT_SET, 1);
  assert.equal(summary.suppressed.true, 1);
  assert.equal(summary.suppressed.false, 1);
});
