import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Script } from "node:vm";

const html = await readFile(new URL("../docs/index.html", import.meta.url), "utf8");
const scripts = [...html.matchAll(/<script\\b[^>]*>([\\s\\S]*?)<\\/script>/gi)].map(match => match[1]);
const ids = [...html.matchAll(/\\bid=["']([^"']+)["']/g)].map(match => match[1]);
const fragments = [...html.matchAll(/\\bhref=["']#([^"']+)["']/g)].map(match => match[1]);

test("field manual is a complete HTML document with a useful title", () => {
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /<html\\s+lang=["']en["']/i);
  assert.match(html, /<title>Vanguard/);
  assert.match(html, /<meta\\s+name=["']description["']/i);
});

test("all in-page navigation targets exist and IDs are unique", () => {
  assert.equal(new Set(ids).size, ids.length, "HTML id attributes must be unique");
  for (const fragment of fragments) {
    assert.ok(ids.includes(fragment), `Missing in-page target: #${fragment}`);
  }
});

test("the interactive packet lab exposes its controls and live status", () => {
  for (const id of [
    "demo", "key-btn", "event-btn", "relay-btn", "sync-btn", "reset-btn",
    "packet-list", "lab-status", "inspector", "toggle-trust", "tamper", "verify-again"
  ]) {
    assert.ok(ids.includes(id), `Missing packet-lab element: #${id}`);
  }
  assert.match(html, /id=["']lab-status["'][^>]*role=["']status["']/);
  assert.match(html, /aria-live=["']polite["']/);
});

test("the manual clearly distinguishes simulation from real persistence and sync", () => {
  assert.match(html, /No SQLite database, radio or server was contacted/);
  assert.match(html, /not a real gateway response/);
  assert.match(html, /does not contact Supabase/);
  assert.match(html, /not Vanguard’s server-signed campus registry/);
});

test("the site documents security and deployment limitations", () => {
  for (const term of ["SQLCipher", "Android Keystore", "24 KiB", "physical", "author policy"]) {
    assert.ok(html.toLowerCase().includes(term.toLowerCase()), `Missing operational/security detail: ${term}`);
  }
  assert.match(html, /GitHub API unavailable/);
  assert.match(html, /NO RELEASE/);
});

test("all inline JavaScript parses without executing browser side effects", () => {
  assert.ok(scripts.length > 0, "Expected the self-contained packet-lab script");
  scripts.forEach((source, index) => {
    assert.doesNotThrow(
      () => new Script(source, { filename: `docs/index.html:inline-script-${index + 1}` }),
      `Inline script ${index + 1} must be syntactically valid`
    );
  });
});

test("the page contains no placeholder outbound links", () => {
  const hrefs = [...html.matchAll(/\\bhref=["']([^"']+)["']/gi)].map(match => match[1]);
  for (const href of hrefs) {
    assert.doesNotMatch(href, /example\\.com|TODO|PLACEHOLDER/i, `Placeholder link found: ${href}`);
  }
});
