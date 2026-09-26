/**
 * Every check is a pure function of (pkg, entry) -> findings[].
 *
 * A finding must carry evidence a human can open: file and line, or a field from
 * a manifest. A check that cannot point at something does not get to report.
 */

const SECRETISH = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|ACCESS|BEARER|DSN|WEBHOOK)/i;

/** Environment variables that are ambient, not credentials the user must supply. */
const AMBIENT = new Set([
  'NODE_ENV', 'NODE_OPTIONS', 'NODE_PATH', 'PATH', 'HOME', 'USER', 'USERPROFILE', 'PWD', 'CWD',
  'TMPDIR', 'TEMP', 'TMP', 'SHELL', 'TERM', 'LANG', 'LC_ALL', 'TZ', 'CI', 'DEBUG', 'NO_COLOR',
  'FORCE_COLOR', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME',
  'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'PORT', 'HOSTNAME', 'OS', 'COMSPEC', 'SystemRoot',
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
]);

const OFFICIAL_PREFIX = '@modelcontextprotocol/';

function* eachLine(files) {
  for (const [path, buf] of files) {
    if (path === 'package.json') continue;
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
        if (AMBIENT.has(name) || name.startsWith('npm_')) continue;
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
    const secretish = SECRETISH.test(name);
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
  const scripts = pkg.manifest?.scripts ?? {};
  const risky = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];
  return risky
    .filter((k) => scripts[k])
    .map((k) => ({
      check: 'install-script',
      severity: k === 'prepare' || k === 'prepublish' ? 'low' : 'high',
      message: `runs a ${k} script on install: ${trim(scripts[k], 80)}`,
      evidence: [{ file: 'package.json', line: 0, text: `"${k}": "${trim(scripts[k], 100)}"` }],
    }));
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
  if (!repo) {
    findings.push({
      check: 'provenance',
      severity: 'medium',
      message: 'no repository field: the published code cannot be traced to source',
      evidence: [{ file: 'package.json', line: 0, text: 'repository: absent' }],
    });
  }
  if (pkg.integrityOk === false) {
    findings.push({
      check: 'provenance',
      severity: 'high',
      message: 'tarball does not match the integrity hash npm published for it',
      evidence: [{ file: 'dist.integrity', line: 0, text: 'mismatch' }],
    });
  }
  if (pkg.versionCount === 1) {
    findings.push({
      check: 'provenance',
      severity: 'low',
      message: 'only one version ever published',
      evidence: [{ file: 'npm', line: 0, text: `versions: ${pkg.versionCount}` }],
    });
  }
  if (pkg.publishedAt) {
    const days = Math.floor((Date.now() - Date.parse(pkg.publishedAt)) / 86400000);
    if (days < 14) {
      findings.push({
        check: 'provenance',
        severity: 'low',
        message: `published ${days} day(s) ago`,
        evidence: [{ file: 'npm', line: 0, text: pkg.publishedAt }],
      });
    }
  }
  return findings;
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

export const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

export function runAllChecks({ pkg, entry, declared, officialNames }) {
  return [
    ...checkUndeclaredSecrets(pkg, entry, declared),
    ...checkInstallScripts(pkg),
    ...checkProvenance(pkg),
    ...checkTyposquat(pkg, officialNames),
    ...checkNetworkEgress(pkg, entry),
    ...checkCapabilities(pkg),
  ].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
