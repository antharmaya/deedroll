/**
 * Pin every tool a remote server serves, and report changes on the next probe: the
 * rug pull — a server that looked fine when approved rewrites a tool later, and the
 * agent reads the new text.
 *
 * Pins are NEVER updated automatically when something changed. If the new state
 * silently became the baseline, the alert would fire once and vanish for good.
 * Accepting a change takes --update-pins.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, renameSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

export function pinsPath() {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'mcpscan', 'pins.json');
}

/** Stable JSON: key order must not make an unchanged tool look changed. */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

const hash = (v) => createHash('sha256').update(canonical(v)).digest('hex').slice(0, 16);

/** What is pinned per tool: what the agent reads (description) and what it sends (schema). */
export function fingerprint(tool) {
  return {
    description: hash(tool.description ?? ''),
    schema: hash(tool.inputSchema ?? null),
    text: String(tool.description ?? '').slice(0, 2000),
  };
}

/** The pin key: the URL without userinfo. Query strings stay — they select tools (apify ?tools=). */
export function serverKey(url) {
  const u = new URL(url);
  u.username = '';
  u.password = '';
  return u.toString();
}

export function loadPins(path = pinsPath()) {
  try {
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {};
  } catch {
    return {};
  }
}

export function savePins(pins, path = pinsPath()) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(pins, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, path);
}

function snippet(s, n = 140) {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

/**
 * Compare a fresh tool list with the pinned one.
 * @returns {{findings: object[], changed: boolean, firstPin: boolean, next: object}}
 */
export function diffPins(previous, tools, { now = new Date().toISOString() } = {}) {
  const current = Object.fromEntries(tools.map((t) => [t.name, fingerprint(t)]));
  const next = { pinnedAt: previous?.pinnedAt ?? now, checkedAt: now, tools: current };
  if (!previous?.tools) {
    return {
      findings: [
        {
          check: 'pinned',
          severity: 'info',
          message: `first probe: pinned ${tools.length} tool(s); later changes to any of them will be reported`,
          evidence: [{ file: 'pins.json', line: 0, text: `${tools.length} tools` }],
        },
      ],
      changed: false,
      firstPin: true,
      next: { ...next, pinnedAt: now },
    };
  }

  const findings = [];
  const since = String(previous.pinnedAt).slice(0, 10);
  for (const [name, fp] of Object.entries(current)) {
    const old = previous.tools[name];
    if (!old) {
      findings.push({
        check: 'tool-added',
        subject: name,
        severity: 'medium',
        message: `tool "${name}" appeared since the pin of ${since}: "${snippet(fp.text)}"`,
        evidence: [{ file: 'pins.json', line: 0, text: `new: ${name}` }],
      });
      continue;
    }
    if (old.description !== fp.description) {
      findings.push({
        check: 'tool-description-changed',
        subject: name,
        severity: 'high',
        message: `tool "${name}" changed its description since the pin of ${since} — what your agent reads is not what was approved`,
        evidence: [
          { file: 'was', line: 0, text: snippet(old.text) },
          { file: 'now', line: 0, text: snippet(fp.text) },
        ],
      });
    } else if (old.schema !== fp.schema) {
      findings.push({
        check: 'tool-schema-changed',
        subject: name,
        severity: 'medium',
        message: `tool "${name}" changed its input schema since the pin of ${since}`,
        evidence: [{ file: 'pins.json', line: 0, text: `schema ${old.schema} -> ${fp.schema}` }],
      });
    }
  }
  for (const name of Object.keys(previous.tools)) {
    if (!current[name]) {
      findings.push({
        check: 'tool-removed',
        subject: name,
        severity: 'low',
        message: `tool "${name}" is gone since the pin of ${since}`,
        evidence: [{ file: 'pins.json', line: 0, text: `removed: ${name}` }],
      });
    }
  }
  return { findings, changed: findings.length > 0, firstPin: false, next };
}
