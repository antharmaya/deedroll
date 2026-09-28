/**
 * Tool pinning, platform-neutral: the same fingerprints and the same diff in the CLI
 * (pins stored in ~/.config/mcpscan/pins.json) and in the browser (pins stored in the
 * visitor's own browser). A hosted server can rewrite a tool's description after it was
 * approved; the only defence is remembering what it said.
 */

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

/** First 16 hex chars of sha256 over the canonical form, via Web Crypto. */
export async function sha16(v) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical(v))));
  return [...bytes.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** What is pinned per tool: what the agent reads (description) and what it sends (schema). */
export async function fingerprintTool(tool) {
  return {
    description: await sha16(tool.description ?? ''),
    schema: await sha16(tool.inputSchema ?? null),
    text: String(tool.description ?? '').slice(0, 2000),
  };
}

export async function fingerprintTools(tools) {
  return Object.fromEntries(await Promise.all(tools.map(async (t) => [t.name, await fingerprintTool(t)])));
}

/** The pin key: the URL without userinfo. Query strings stay: they select tools (apify ?tools=). */
export function serverKey(url) {
  const u = new URL(url);
  u.username = '';
  u.password = '';
  return u.toString();
}

function snippet(s, n = 140) {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

/**
 * Compare fresh fingerprints (from fingerprintTools) with the pinned ones.
 * @returns {{findings: object[], changed: boolean, firstPin: boolean, next: object}}
 */
export function diffFingerprints(previous, current, { now = new Date().toISOString(), store = 'pins.json' } = {}) {
  const tools = Object.keys(current);
  const next = { pinnedAt: previous?.pinnedAt ?? now, checkedAt: now, tools: current };
  if (!previous?.tools) {
    return {
      findings: [
        {
          check: 'pinned',
          severity: 'info',
          message: `first probe: pinned ${tools.length} tool(s); later changes to any of them will be reported`,
          evidence: [{ file: store, line: 0, text: `${tools.length} tools` }],
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
        evidence: [{ file: store, line: 0, text: `new: ${name}` }],
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
        evidence: [{ file: store, line: 0, text: `schema ${old.schema} -> ${fp.schema}` }],
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
        evidence: [{ file: store, line: 0, text: `removed: ${name}` }],
      });
    }
  }
  return { findings, changed: findings.length > 0, firstPin: false, next };
}
