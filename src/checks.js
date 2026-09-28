/**
 * Every check is a pure function of (pkg, entry) -> findings[].
 *
 * A finding must carry evidence a human can open: file and line, or a field from
 * a manifest. A check that cannot point at something does not get to report.
 */

import { extractTools } from './tools.js';

const SECRETISH = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|ACCESS|BEARER|DSN|WEBHOOK)/i;

/**
 * Names that point AT something rather than being the secret: OAUTH_AUTH_SERVER_URL,
 * INITE_TOKEN_FILE. Matching "AUTH" or "TOKEN" in them was a false positive found on
 * a real machine (2026-09-27). Webhook URLs are the exception — the URL is the secret.
 */
const LOCATOR_SUFFIX = /_(URL|URI|ENDPOINT|HOST|HOSTNAME|DOMAIN|ISSUER|AUDIENCE|FILE|PATH|DIR|PORT)$/i;

/**
 * On/off switches and quantities that mention a secret word: FIRECRAWL_MCP_SEARCH_OAUTH_ONLY,
 * MCP_OAUTH_ACCEPT_LEGACY_V2_MCP_AUD, JDOCMUNCH_SESSION_TOKEN_BUDGET (all found live).
 */
const FLAG_SUFFIX = /_(ONLY|ENABLED|ENABLE|DISABLED|DISABLE|MODE|AUD|STRICT|REQUIRED|DEBUG|VERBOSE|TIMEOUT|TTL|LIMIT|COUNT|RETRIES|BUDGET|SIZE|LENGTH|THRESHOLD|INTERVAL|DELAY|HOURS|DAYS|MINUTES|SECONDS|MS)$/i;

/**
 * The secret word has to END a segment of the name. Matching it anywhere flagged
 * KEYCLOAK_REALM (KEY-cloak), CLIO_LEXICAL_MAX_TOKENS_PER_CHUNK (a count of tokens) and
 * would flag GIT_AUTHOR_NAME (AUTH-or); all three found or implied by the PyPI benchmark
 * of 2026-09-28. A segment ending in the word still counts: OPENAIKEY, API_KEYS.
 */
const SECRET_SEGMENT = /(KEYS?|TOKEN|SECRETS?|PASSWORD|PASSWD|CREDENTIALS?|AUTH|AUTHORIZATION|PRIVATE|ACCESS|BEARER|DSN|WEBHOOK)$/;

/** One definition of "this env var name holds a credential", shared by every check. */
export function isCredentialName(name) {
  if (!SECRETISH.test(name)) return false;
  if (!String(name).toUpperCase().split(/[_.-]+/).some((seg) => SECRET_SEGMENT.test(seg))) return false;
  if (LOCATOR_SUFFIX.test(name) && !/WEBHOOK/i.test(name)) return false;
  if (FLAG_SUFFIX.test(name)) return false;
  return true;
}

/** Environment variables that are ambient, not credentials the user must supply. */
const AMBIENT = new Set([
  'NODE_ENV', 'NODE_OPTIONS', 'NODE_PATH', 'PATH', 'HOME', 'USER', 'USERPROFILE', 'PWD', 'CWD',
  'TMPDIR', 'TEMP', 'TMP', 'SHELL', 'TERM', 'LANG', 'LC_ALL', 'TZ', 'CI', 'DEBUG', 'NO_COLOR',
  'FORCE_COLOR', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME',
  'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'PORT', 'HOSTNAME', 'OS', 'COMSPEC', 'SystemRoot',
  // Python's own runtime variables (PYTHON* is skipped by prefix): set by the interpreter or the user's shell.
  'VIRTUAL_ENV', 'CONDA_PREFIX',
]);

const ENV_PATTERNS = [
  /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /process\.env\[\s*['"`]([^'"`]+)['"`]\s*\]/g,
  /os\.environ\.get\(\s*['"]([^'"]+)['"]/g,
  /os\.environ\[\s*['"]([^'"]+)['"]\s*\]/g,
  /getenv\(\s*['"]([^'"]+)['"]/g,
];

const CAPABILITY_PATTERNS = [
  { re: /\bchild_process\b|\bexecSync\s*\(|\bspawnSync\s*\(|\bexec\s*\(/, label: 'process execution' },
  { re: /\beval\s*\(|new\s+Function\s*\(|\bvm\.runIn/, label: 'dynamic code evaluation' },
  { re: /\bsubprocess\.|\bos\.system\s*\(|\bpopen\s*\(/, label: 'process execution (python)' },
  { re: /\bfs\.(unlink|rm|rmdir|rmSync|unlinkSync|writeFile|writeFileSync)\b|\bshutil\.rmtree\b/, label: 'filesystem writes or deletes' },
  { re: /\bnet\.(connect|createConnection)\b|\bdgram\b/, label: 'raw network sockets' },
];

const URL_RE = /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi;

/** Hosts that are infrastructure, not exfiltration surface. */
const BENIGN_HOSTS = new Set([
  'registry.npmjs.org', 'npmjs.com', 'www.npmjs.com', 'nodejs.org', 'github.com', 'www.github.com',
  'raw.githubusercontent.com', 'json-schema.org', 'schema.org', 'www.w3.org', 'opensource.org',
  'spdx.org', 'localhost', 'example.com', 'www.example.com', 'modelcontextprotocol.io',
  'static.modelcontextprotocol.io', 'registry.modelcontextprotocol.io',
  'pypi.org', 'files.pythonhosted.org', 'python.org', 'www.python.org', 'docs.python.org',
]);

const OFFICIAL_PREFIX = '@modelcontextprotocol/';

/** Where package metadata lives, per ecosystem: evidence should name the real source. */
const META = {
  npm: { file: 'package.json', registry: 'npm' },
  pypi: { file: 'PyPI metadata', registry: 'PyPI' },
};
const meta = (pkg) => META[pkg.ecosystem ?? 'npm'] ?? META.npm;

function* eachLine(files) {
  for (const [path, buf] of files) {
    if (path === 'package.json' || path.endsWith('/package.json')) continue; // manifests, not code
    const text = buf.toString('utf8');
    if (text.includes('\0')) continue; // binary
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      yield { path, line: i + 1, text: lines[i] };
    }
  }
}

function trim(s, n = 160) {
  const t = s.trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

/** CHECK 1 — credentials the code reads that the registry entry never declares. */
export function checkUndeclaredSecrets(pkg, entry, declared) {
  const found = new Map(); // NAME -> evidence[]
  for (const { path, line, text } of eachLine(pkg.files)) {
    for (const re of ENV_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const name = m[1];
        if (AMBIENT.has(name) || name.startsWith('npm_') || name.startsWith('PYTHON')) continue;
        if (!found.has(name)) found.set(name, []);
        const ev = found.get(name);
        if (ev.length < 3) ev.push({ file: path, line, text: trim(text) });
      }
    }
  }

  const findings = [];
  for (const [name, evidence] of found) {
    if (declared?.has(name)) continue;
    if (name.includes('${') || name.includes('+')) {
      // A computed name like `${prefix}_API_KEY`. Static analysis cannot resolve it,
      // and reporting the template as if it were a variable name would be a lie.
      findings.push({
        check: 'dynamic-env',
        subject: name,
        severity: 'info',
        message: `builds an environment variable name at runtime (${name}); static analysis cannot resolve it`,
        evidence,
      });
      continue;
    }
    const secretish = isCredentialName(name);
    findings.push({
      check: 'undeclared-env',
      subject: name,
      severity: secretish ? (entry ? 'high' : 'medium') : 'low',
      message: entry
        ? `reads ${name}${secretish ? ' (looks like a credential)' : ''} but the registry entry does not declare it`
        : `reads ${name}${secretish ? ' (looks like a credential)' : ''}; no registry entry to declare it`,
      evidence,
    });
  }
  return findings;
}

/** CHECK 2 — lifecycle scripts, the classic supply-chain vector. */
export function checkInstallScripts(pkg) {
  if (pkg.ecosystem === 'pypi') return checkPythonBuild(pkg);
  const scripts = pkg.manifest?.scripts ?? {};
  // Only these run when a package is installed as a dependency or via npx. `prepare`
  // does not ("does not run when installing specific packages like npm install
  // express" — npm docs); flagging it was a false positive on every official server.
  const risky = ['preinstall', 'install', 'postinstall'];
  return risky
    .filter((k) => scripts[k])
    .map((k) => ({
      check: 'install-script',
      severity: 'high',
      message: `runs a ${k} script on install: ${trim(scripts[k], 80)}`,
      evidence: [{ file: 'package.json', line: 0, text: `"${k}": "${trim(scripts[k], 100)}"` }],
    }));
}

/**
 * CHECK 2b — install scripts in followed dependencies. npm runs a dependency's
 * preinstall/install/postinstall on the user's machine too, so they count as much as
 * the root's. Only dependencies mcpscan actually followed (--deps) are covered.
 */
export function checkDependencyInstallScripts(pkg) {
  const out = [];
  for (const d of pkg.dependencies ?? []) {
    const scripts = d.manifest?.scripts ?? {};
    for (const k of ['preinstall', 'install', 'postinstall']) {
      if (!scripts[k]) continue;
      out.push({
        check: 'install-script',
        severity: 'high',
        message: `dependency ${d.name}@${d.version} runs a ${k} script on install: ${trim(scripts[k], 80)}`,
        evidence: [{ file: `node_modules/${d.name}/package.json`, line: 0, text: `"${k}": "${trim(scripts[k], 100)}"` }],
      });
    }
  }
  return out;
}

/** CHECK 3 — every external host the code can reach. */
export function checkNetworkEgress(pkg, entry) {
  const declaredHosts = new Set();
  for (const r of entry?.server?.remotes ?? []) {
    try { declaredHosts.add(new URL(r.url).hostname); } catch { /* malformed url in entry */ }
  }
  try {
    const repo = pkg.manifest?.repository?.url ?? pkg.manifest?.repository;
    if (typeof repo === 'string') declaredHosts.add(new URL(repo.replace(/^git\+/, '').replace(/^git:/, 'https:')).hostname);
  } catch { /* no parseable repository field */ }

  const hosts = new Map();
  for (const { path, line, text } of eachLine(pkg.files)) {
    URL_RE.lastIndex = 0;
    let m;
    while ((m = URL_RE.exec(text)) !== null) {
      const host = m[1].toLowerCase();
      if (BENIGN_HOSTS.has(host) || declaredHosts.has(host)) continue;
      if (!hosts.has(host)) hosts.set(host, []);
      const ev = hosts.get(host);
      if (ev.length < 2) ev.push({ file: path, line, text: trim(text) });
    }
  }

  return [...hosts].map(([host, evidence]) => ({
    check: 'network-egress',
    severity: 'info',
    message: `contacts ${host}`,
    evidence,
  }));
}

/** CHECK 4 — capabilities that decide blast radius if the server is compromised. */
export function checkCapabilities(pkg) {
  const hits = new Map();
  for (const { path, line, text } of eachLine(pkg.files)) {
    for (const { re, label } of CAPABILITY_PATTERNS) {
      if (!re.test(text)) continue;
      if (!hits.has(label)) hits.set(label, []);
      const ev = hits.get(label);
      if (ev.length < 3) ev.push({ file: path, line, text: trim(text) });
    }
  }
  return [...hits].map(([label, evidence]) => ({
    check: 'capability',
    severity: 'info',
    message: `uses ${label}`,
    evidence,
  }));
}

/** CHECK 5 — who published this, and can you trace it back. */
export function checkProvenance(pkg) {
  const findings = [];
  const repo = pkg.manifest?.repository;
  // A signed build attestation naming the source repository makes the code traceable even
  // when the metadata links nowhere (mcp-server-sqlite: built from modelcontextprotocol/servers).
  const attested = pkg.provenance?.current && pkg.provenance?.publisher?.repository;
  if (!repo && !attested) {
    findings.push({
      check: 'provenance',
      severity: 'medium',
      message: pkg.ecosystem === 'pypi'
        ? 'no source repository in its project URLs: the published code cannot be traced to source'
        : 'no repository field: the published code cannot be traced to source',
      evidence: [{ file: meta(pkg).file, line: 0, text: 'repository: absent' }],
    });
  }
  if (pkg.integrityOk === false) {
    findings.push({
      check: 'provenance',
      severity: 'high',
      message: `download does not match the integrity hash ${meta(pkg).registry} published for it`,
      evidence: [{ file: 'dist.integrity', line: 0, text: 'mismatch' }],
    });
  }
  if (pkg.versionCount === 1) {
    findings.push({
      check: 'provenance',
      severity: 'low',
      message: 'only one version ever published',
      evidence: [{ file: meta(pkg).registry, line: 0, text: `versions: ${pkg.versionCount}` }],
    });
  }
  if (pkg.publishedAt) {
    const days = Math.floor((Date.now() - Date.parse(pkg.publishedAt)) / 86400000);
    if (days < 14) {
      findings.push({
        check: 'provenance',
        severity: 'low',
        message: `published ${days} day(s) ago`,
        evidence: [{ file: meta(pkg).registry, line: 0, text: pkg.publishedAt }],
      });
    }
  }
  return findings;
}

/**
 * CHECK 7 — npm itself has marked this version deprecated. Free: the notice is already
 * in the manifest we downloaded. Found live: @modelcontextprotocol/server-github is
 * deprecated ("Package no longer supported") yet still installed ~129k times a week.
 */
export function checkDeprecated(pkg) {
  const note = pkg.manifest?.deprecated;
  if (!note) return [];
  return [
    {
      check: 'deprecated',
      severity: 'medium',
      message: pkg.ecosystem === 'pypi'
        ? `PyPI marks ${pkg.name} ${pkg.version} yanked: ${String(note).slice(0, 140)}`
        : `npm marks ${pkg.name}@${pkg.version} deprecated: ${String(note).slice(0, 140)}`,
      evidence: [{ file: meta(pkg).registry, line: 0, text: `${pkg.ecosystem === 'pypi' ? 'yanked' : 'deprecated'}: ${String(note).slice(0, 100)}` }],
    },
  ];
}

/**
 * CHECK 8 — provenance dropped. Earlier versions carried an npm provenance attestation
 * (built by CI from a named repo) and this one does not. Absence alone is normal for
 * small packages and is not flagged; the drop is what matters.
 */
export function checkProvenanceDrop(pkg) {
  const p = pkg.provenance;
  // "unknown" (the registry did not answer) must never read as "absent".
  if (!p || p.current || p.state === 'unknown' || p.earlierWithProvenance === 0) return [];
  return [
    {
      check: 'provenance-dropped',
      severity: 'medium',
      message: `${pkg.name}@${pkg.version} has no provenance attestation, but ${p.earlierWithProvenance} earlier version(s) did (last: ${p.lastWithProvenance}) — published outside the usual CI pipeline?`,
      evidence: [{ file: meta(pkg).registry, line: 0, text: `attestations: absent (present on ${p.lastWithProvenance})` }],
    },
  ];
}

/**
 * CHECK 9 — tool descriptions written to instruct the model rather than inform the
 * user: the shape of tool-poisoning attacks. It also protects the agent judge, which
 * reads these same descriptions.
 *
 * Patterns were measured before they shipped, on 312 real descriptions from 27 vendor
 * servers (2026-09-28): the two high-severity ones hit 0. Dropped after measuring:
 * "you must call ..." (Shopify's legitimate usage guidance), bare `.env` (Neon telling
 * users where their own config goes) and XML-style tags on their own (Neon structures
 * every description with <use_case>, <instructions>, <important_notes>).
 */
const INJECTION_PATTERNS = [
  {
    id: 'ignore-instructions',
    severity: 'high',
    re: /\b(ignore|disregard|forget)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instructions?|prompts?|rules)\b/i,
    label: 'tells the model to ignore its instructions',
  },
  {
    id: 'hide-from-user',
    severity: 'high',
    re: /\b(do not|don't|never)\b[^.\n]{0,20}\b(tell|inform|mention|reveal|show|notify)\b[^.\n]{0,60}\bthe user\b/i,
    label: 'tells the model to keep something from the user',
  },
  {
    id: 'credential-store',
    severity: 'medium',
    // Directing the model to READ or SEND the file is the attack; merely mentioning it is not.
    // Measured: flatland-client says "Back up ~/.flatland/models/ like ~/.ssh/" — an analogy,
    // the only hit in 5,499 long-tail descriptions before this verb was required.
    re: /\b(read|open|cat|load|send|pass|include|upload|attach|forward|copy|print|return|exfiltrate)\b[^.\n]{0,40}(~\/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws\/credentials|\bmcp\.json\b|claude_desktop_config|\.cursor\/mcp)/i,
    label: 'tells the model to read or send a credential store or agent config file',
  },
];
const HIDDEN_TAG = /<\s*\/?\s*(important|system|secret|hidden)\s*>/i;

export function checkInstructionLikeText(pkg) {
  return checkToolTexts(extractTools(pkg.files).tools);
}

/** The same check over any tool list: a package's extracted tools or a remote server's served ones. */
export function checkToolTexts(tools) {
  const out = [];
  for (const t of tools) {
    for (const p of INJECTION_PATTERNS) {
      const m = p.re.exec(t.description);
      if (!m) continue;
      const tag = HIDDEN_TAG.test(t.description) ? ', inside a hidden-instruction tag' : '';
      out.push({
        check: 'instruction-like-text',
        subject: `${t.name}:${p.id}`,
        severity: p.severity,
        message: `tool "${t.name}" description ${p.label}${tag}: "${m[0].slice(0, 90)}"`,
        evidence: [{ file: t.file, line: t.line, text: t.description.slice(Math.max(0, m.index - 40), m.index + 100) }],
      });
    }
  }
  return out;
}

/** Levenshtein, iterative, two rows. */
export function editDistance(a, b) {
  if (a === b) return 0;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
    prev = cur;
  }
  return prev[b.length];
}

/**
 * CHECK 6 — name confusable with an official package.
 * The unscoped-vs-scoped case is the one that has actually bitten this project twice.
 */
export function checkTyposquat(pkg, officialNames = []) {
  if ((pkg.ecosystem ?? 'npm') !== 'npm') return []; // the official list is npm names
  const name = pkg.name;
  if (name.startsWith(OFFICIAL_PREFIX)) return [];
  const bare = name.replace(/^@[^/]+\//, '');
  const findings = [];

  for (const official of officialNames) {
    const officialBare = official.replace(OFFICIAL_PREFIX, '');
    const d = editDistance(bare, officialBare);
    if (d === 0) {
      findings.push({
        check: 'typosquat',
        severity: 'high',
        message: `unscoped "${name}" shares its name with the official ${official}`,
        evidence: [{ file: 'package.json', line: 0, text: `name: ${name}` }],
      });
    } else if (d <= 2 && officialBare.length > 5) {
      findings.push({
        check: 'typosquat',
        severity: 'medium',
        message: `name is ${d} character(s) from the official ${official}`,
        evidence: [{ file: 'package.json', line: 0, text: `name: ${name}` }],
      });
    }
  }
  return findings;
}

/**
 * CHECK 2 (PyPI) — code that runs at install. A wheel installs by copying files; with no
 * wheel published, pip builds the sdist, and the build runs the package's own code
 * (setup.py, or the build backend's hooks) on the installing machine: the Python
 * equivalent of an npm install script.
 */
export function checkPythonBuild(pkg) {
  if (!pkg.artifact?.buildsFromSource) return [];
  const setup = pkg.files.get('setup.py');
  return [
    {
      check: 'install-script',
      severity: setup ? 'high' : 'medium',
      message: setup
        ? 'publishes no wheel, so installing it runs its setup.py'
        : 'publishes no wheel, so installing it builds from source and runs its build hooks',
      evidence: [{ file: setup ? 'setup.py' : pkg.artifact.filename, line: 0, text: setup ? trim(setup.toString('utf8').split('\n').find((l) => /setup\(/.test(l)) ?? 'setup.py') : 'sdist only' }],
    },
  ];
}

/**
 * CHECK 8b — built from somewhere else. The provenance attestation names the repository
 * the release was actually built from; the project names the repository it points
 * people at. When both exist and differ, the code you install did not come from the
 * code you would read.
 */
export function checkPublisherMismatch(pkg) {
  const built = pkg.provenance?.publisher?.repository?.toLowerCase();
  const claimed = pkg.provenance?.sourceSlug;
  if (!built || !claimed || built === claimed) return [];
  return [
    {
      check: 'publisher-mismatch',
      severity: 'medium',
      message: `built from ${built} (per its provenance attestation) but its project points at ${claimed}`,
      evidence: [{ file: meta(pkg).registry, line: 0, text: `attestation repository: ${built}; project URL: ${claimed}` }],
    },
  ];
}

/**
 * Reference servers the MCP project moved to modelcontextprotocol/servers-archived (listed
 * 2026-09-28): no longer maintained. npm marks its copies deprecated; PyPI does not yank
 * the Python ones (mcp-server-sqlite, mcp-server-sentry), so they looked current. The NSA's
 * MCP guidance (May 2026) opens its recommendations with "choose supported MCP projects".
 */
const ARCHIVED_REFERENCE = {
  npm: new Set(['brave-search', 'everart', 'gdrive', 'github', 'gitlab', 'google-maps', 'postgres', 'puppeteer', 'redis', 'slack'].map((n) => `@modelcontextprotocol/server-${n}`)),
  pypi: new Set(['mcp-server-sqlite', 'mcp-server-sentry']),
};

export function checkArchivedUpstream(pkg) {
  const eco = pkg.ecosystem ?? 'npm';
  const name = eco === 'pypi' ? String(pkg.name).toLowerCase().replace(/[-_.]+/g, '-') : pkg.name;
  if (!ARCHIVED_REFERENCE[eco]?.has(name) || pkg.manifest?.deprecated) return [];
  return [
    {
      check: 'archived-upstream',
      severity: 'medium',
      message: `${pkg.name} is a reference server the MCP project has archived: no longer maintained, and ${meta(pkg).registry} does not mark it`,
      evidence: [{ file: 'modelcontextprotocol/servers-archived', line: 0, text: pkg.name }],
    },
  ];
}

export const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

export function runAllChecks({ pkg, entry, declared, officialNames }) {
  return [
    ...checkUndeclaredSecrets(pkg, entry, declared),
    ...checkInstallScripts(pkg),
    ...checkDependencyInstallScripts(pkg),
    ...checkProvenance(pkg),
    ...checkDeprecated(pkg),
    ...checkProvenanceDrop(pkg),
    ...checkArchivedUpstream(pkg),
    ...checkPublisherMismatch(pkg),
    ...checkInstructionLikeText(pkg),
    ...checkTyposquat(pkg, officialNames),
    ...checkNetworkEgress(pkg, entry),
    ...checkCapabilities(pkg),
  ].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
