import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig, parseCliArgs } from "../src/config.js";

test("parseCliArgs recognizes help and insecure tls", () => {
  const cli = parseCliArgs(["-h", "--insecure-tls", "true"]);
  assert.equal(cli.help, true);
  assert.equal(cli.insecureTls, true);
});

test("loadConfig reads insecure tls from env", () => {
  const config = loadConfig([], {
    DTRACK_BASE_URL: "https://dtrack.example/api",
    DTRACK_API_KEY: "secret",
    DTRACK_INSECURE_TLS: "true"
  });

  assert.equal(config.insecureTls, true);
});

test("loadConfig allows overriding insecure tls with cli", () => {
  const config = loadConfig(["--insecure-tls", "false"], {
    DTRACK_BASE_URL: "https://dtrack.example/api",
    DTRACK_API_KEY: "secret",
    DTRACK_INSECURE_TLS: "true"
  });

  assert.equal(config.insecureTls, false);
});
