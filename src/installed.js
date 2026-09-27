/**
 * `--installed`: find every MCP server the user's agents already trust, without
 * launching any of them.
 *
 * These config files hold live API keys. The rule that makes this safe: values are
 * dropped HERE, at the parser. Everything downstream sees an env var's name and
 * whether it was a literal or a ${REFERENCE} — never its value — and raw args are
 * never echoed, because args carry tokens too. A later bug in rendering or JSON
 * output cannot leak what no longer exists.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';
import { isCredentialName } from './checks.js';
const ENV_REFERENCE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/;

/** Where each agent keeps its MCP config. JSON ones share the `mcpServers` shape. */
function configLocations(home, cwd) {
  return [
    { agent: 'claude-code', file: join(home, '.claude.json'), format: 'claude-json' },
    { agent: 'claude-code', file: join(cwd, '.mcp.json'), format: 'mcp-json', scope: 'project' },
    { agent: 'codex', file: join(home, '.codex', 'config.toml'), format: 'codex-toml' },
    { agent: 'claude-desktop', file: join(home, '.config', 'Claude', 'claude_desktop_config.json'), format: 'mcp-json' },
    { agent: 'claude-desktop', file: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), format: 'mcp-json' },
    { agent: 'cursor', file: join(home, '.cursor', 'mcp.json'), format: 'mcp-json' },
    { agent: 'windsurf', file: join(home, '.codeium', 'windsurf', 'mcp_config.json'), format: 'mcp-json' },
    { agent: 'gemini-cli', file: join(home, '.gemini', 'settings.json'), format: 'mcp-json' },
  ];
}

/** Reduce an env/header map to names plus literal-vs-reference. Values stop here. */
function redact(map) {
  const out = {};
  for (const [k, v] of Object.entries(map ?? {})) {
    const s = typeof v === 'string' ? v.trim() : '';
    out[k] = { literal: s.length > 0 && !ENV_REFERENCE.test(s) };
  }
  return out;
}

/** Args are kept only as a count plus the names of any secret-looking flags. */
function summariseArgs(args = []) {
  const secretFlags = [];
  for (const a of args) {
    const m = /^--?([A-Za-z0-9_-]+)=(.+)$/.exec(String(a));
    if (m && isCredentialName(m[1]) && !ENV_REFERENCE.test(m[2])) secretFlags.push(m[1]);
  }
  return { count: args.length, secretFlags };
}

function normaliseServer(name, raw, origin) {
  return {
    name,
    agent: origin.agent,
    file: origin.file,
    scope: origin.scope ?? null,
    type: raw.type ?? (raw.url ? 'http' : 'stdio'),
    command: raw.command ?? null,
    // args are needed once, to resolve the launch; the resolver runs before anything is stored
    launch: resolveLaunch(raw),
    args: summariseArgs(raw.args),
    env: redact(raw.env),
    headers: redact(raw.headers ?? raw.http_headers),
    url: raw.url ? safeHost(raw.url) : null,
  };
}

function safeHost(url) {
  try {
    return new URL(url).host; // host only: query strings carry tokens
  } catch {
    return 'unparseable-url';
  }
}

// ---------------- launch resolution ----------------

function splitSpec(spec) {
  // "@scope/pkg@1.2.3" -> ["@scope/pkg", "1.2.3"]; "pkg" -> ["pkg", null]
  const at = spec.lastIndexOf('@');
  if (at > 0) return [spec.slice(0, at), spec.slice(at + 1) || null];
  return [spec, null];
}

function firstPositional(args, from = 0) {
  for (let i = from; i < args.length; i++) {
    const a = String(args[i]);
    if (a === '-p' || a === '--package') return String(args[i + 1] ?? '');
    if (a.startsWith('--package=')) return a.slice('--package='.length);
    if (!a.startsWith('-')) return a;
  }
  return null;
}

/**
 * What would actually run. Only npm is scannable today; everything else is reported
 * with the reason it is not, so coverage is visible rather than silently partial.
 */
export function resolveLaunch(raw) {
  if (raw.url || /^(http|sse|streamable-http)$/i.test(raw.type ?? '')) {
    return { kind: 'remote', host: raw.url ? safeHost(raw.url) : 'unknown' };
  }
  const cmd = basename(String(raw.command ?? '')).replace(/\.(cmd|exe)$/i, '');
  const args = (raw.args ?? []).map(String);

  let spec = null;
  if (cmd === 'npx' || cmd === 'bunx') spec = firstPositional(args);
  else if (cmd === 'npm' && args[0] === 'exec') spec = firstPositional(args, 1);
  else if ((cmd === 'pnpm' || cmd === 'yarn') && args[0] === 'dlx') spec = firstPositional(args, 1);

  if (spec) {
    const [name, version] = splitSpec(spec);
    const pinned = Boolean(version && /^\d+\.\d+\.\d+/.test(version));
    return { kind: 'npm', name, version, pinned };
  }
  if (cmd === 'uvx' || (cmd === 'uv' && args.includes('run'))) {
    const p = firstPositional(args, cmd === 'uv' ? args.indexOf('run') + 1 : 0);
    const name = p ? p.split(/[@=<>]/)[0] : null;
    return { kind: 'pypi', name, pinned: Boolean(p && /==/.test(p)) };
  }
  if (cmd === 'docker' || cmd === 'podman') return { kind: 'container' };
  if (['node', 'python', 'python3', 'deno', 'bun', 'tsx', 'ts-node'].includes(cmd)) {
    return { kind: 'local', runtime: cmd };
  }
  return { kind: 'binary', command: cmd || 'unknown' };
}

// ---------------- parsers ----------------

function parseJsonServers(text, origin) {
  const d = JSON.parse(text);
  const out = [];
  for (const [name, raw] of Object.entries(d.mcpServers ?? {})) out.push(normaliseServer(name, raw, origin));
  if (origin.format === 'claude-json') {
    for (const [dir, cfg] of Object.entries(d.projects ?? {})) {
      for (const [name, raw] of Object.entries(cfg?.mcpServers ?? {})) {
        out.push(normaliseServer(name, raw, { ...origin, scope: `project:${dir}` }));
      }
    }
  }
  return out;
}

function parseTomlValue(raw) {
  const v = raw.trim();
  if (v.startsWith('"')) return JSON.parse(v.replace(/"\s*(#.*)?$/, '"'));
  if (v.startsWith("'")) return v.slice(1, v.indexOf("'", 1));
  if (v.startsWith('[')) {
    const items = [];
    const re = /"((?:\\.|[^"\\])*)"|'([^']*)'/g;
    let m;
    while ((m = re.exec(v)) !== null) items.push(m[1] !== undefined ? JSON.parse(`"${m[1]}"`) : m[2]);
    return items;
  }
  if (v.startsWith('{')) {
    const table = {};
    const re = /([A-Za-z0-9_-]+|"[^"]+")\s*=\s*("(?:\\.|[^"\\])*"|'[^']*'|[^,}]+)/g;
    let m;
    while ((m = re.exec(v)) !== null) table[m[1].replace(/"/g, '')] = parseTomlValue(m[2]);
    return table;
  }
  return v;
}

/**
 * A deliberately narrow TOML reader: [mcp_servers.<name>] tables and their
 * [mcp_servers.<name>.<sub>] sub-tables, string/array/inline-table values.
 *
 * Trade-off: a full TOML parser means a dependency, and a dependency in a security
 * tool is supply-chain surface. The cost is that exotic TOML (multi-line strings,
 * dotted keys) is not read. Sub-tables like `.env` and `.http_headers` belong to
 * their parent server — reading them as servers is exactly the miscount made on
 * 2026-09-27, when a quick regex reported 15 servers instead of 13.
 */
export function parseCodexToml(text, origin = { agent: 'codex', file: 'config.toml' }) {
  // Fold multi-line arrays onto one line first.
  const lines = [];
  let buf = null;
  let depth = 0;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (buf !== null) {
      buf += ` ${line}`;
      depth += (line.match(/\[/g) ?? []).length - (line.match(/\]/g) ?? []).length;
      if (depth <= 0) {
        lines.push(buf);
        buf = null;
      }
      continue;
    }
    const kv = /^[A-Za-z0-9_-]+\s*=\s*\[/.exec(line);
    if (kv) {
      depth = (line.match(/\[/g) ?? []).length - (line.match(/\]/g) ?? []).length;
      if (depth > 0) {
        buf = line;
        continue;
      }
    }
    lines.push(line);
  }

  const servers = new Map();
  let current = null;
  for (const line of lines) {
    if (!line || line.startsWith('#')) continue;
    const header = /^\[\s*mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_-]+))(?:\.([A-Za-z0-9_-]+))?\s*\]$/.exec(line);
    if (header) {
      const name = header[1] ?? header[2];
      if (!servers.has(name)) servers.set(name, {});
      current = { name, sub: header[3] ?? null };
      continue;
    }
    if (line.startsWith('[')) {
      current = null;
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line);
    if (!current || !kv) continue;
    const target = servers.get(current.name);
    const value = parseTomlValue(kv[2]);
    if (current.sub) {
      target[current.sub] ??= {};
      target[current.sub][kv[1]] = value;
    } else {
      target[kv[1]] = value;
    }
  }

  return [...servers].map(([name, raw]) => normaliseServer(name, raw, { format: 'codex-toml', ...origin }));
}

/**
 * @returns {{configs: Array<{agent, file, servers: number, error?: string}>, servers: object[]}}
 */
export function discoverInstalled({ home = process.env.HOME, cwd = process.cwd() } = {}) {
  const configs = [];
  const servers = [];
  const seen = new Set();

  for (const loc of configLocations(home, cwd)) {
    if (seen.has(loc.file) || !existsSync(loc.file)) continue;
    seen.add(loc.file);
    try {
      const text = readFileSync(loc.file, 'utf8');
      const found =
        loc.format === 'codex-toml' ? parseCodexToml(text, loc) : parseJsonServers(text, loc);
      configs.push({ agent: loc.agent, file: loc.file, servers: found.length });
      servers.push(...found);
    } catch (err) {
      configs.push({ agent: loc.agent, file: loc.file, servers: 0, error: err.message.slice(0, 120) });
    }
  }
  return { configs, servers };
}

// ---------------- config-level findings (no package needed) ----------------

export function configFindings(server) {
  const out = [];
  const { launch } = server;
  const where = { file: server.file, line: 0 };

  if (launch.kind === 'npm' && !launch.pinned) {
    out.push({
      check: 'unpinned-launch',
      severity: 'medium',
      message: `launches ${launch.name}${launch.version ? `@${launch.version}` : ''} unpinned: every start runs whatever version was published last`,
      evidence: [{ ...where, text: `npx ${launch.name}${launch.version ? `@${launch.version}` : ''}` }],
    });
  }
  if (launch.kind === 'pypi' && !launch.pinned) {
    out.push({
      check: 'unpinned-launch',
      severity: 'medium',
      message: `launches ${launch.name ?? 'a PyPI package'} unpinned: every start runs whatever version was published last`,
      evidence: [{ ...where, text: `uvx ${launch.name ?? '?'}` }],
    });
  }
  for (const [k, v] of Object.entries(server.env)) {
    if (v.literal && isCredentialName(k)) {
      out.push({
        check: 'plaintext-secret',
        subject: k,
        severity: 'medium',
        message: `stores ${k} as a plaintext value in the config file`,
        evidence: [{ ...where, text: `env.${k} = <redacted>` }],
      });
    }
  }
  for (const [k, v] of Object.entries(server.headers)) {
    if (v.literal && isCredentialName(k)) {
      out.push({
        check: 'plaintext-secret',
        subject: k,
        severity: 'medium',
        message: `stores the ${k} header as a plaintext value in the config file`,
        evidence: [{ ...where, text: `headers.${k} = <redacted>` }],
      });
    }
  }
  for (const flag of server.args.secretFlags) {
    out.push({
      check: 'plaintext-secret',
      subject: flag,
      severity: 'medium',
      message: `passes --${flag} as a plaintext command-line argument (visible to every process on the machine)`,
      evidence: [{ ...where, text: `--${flag}=<redacted>` }],
    });
  }

  const reasons = {
    remote: `remote server at ${launch.host}: no package to scan statically`,
    pypi: 'PyPI package: static scanning covers npm only today',
    container: 'container image: static scanning covers npm only today',
    local: `local ${launch.runtime} script: local-path scanning not built yet`,
    binary: `runs the ${launch.command} binary: nothing to inspect statically`,
  };
  if (reasons[launch.kind]) {
    out.push({ check: 'not-scanned', severity: 'info', message: reasons[launch.kind], evidence: [{ ...where, text: server.name }] });
  }
  return out;
}
