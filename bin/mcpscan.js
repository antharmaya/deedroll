#!/usr/bin/env node
import { scan } from '../src/index.js';
import { render, renderInstalled, renderRemote, exitCode } from '../src/report.js';
import { scanRemote } from '../src/index.js';
import { resolveHeaderRefs } from '../src/remote.js';
import { auditInstalled } from '../src/audit.js';
import { readFileSync } from 'node:fs';
import { buildDisclosureRequest } from '../src/disclosure.js';
import { buildAgentRequest, createAgentJudge } from '../src/agent-judge.js';
import { toJsonV1, installedToJsonV1, scanToSarif, toRegistryMeta } from '../src/output.js';
import { explain, egressAllowlist, renderLocal } from '../src/report.js';
import { scanLocal } from '../src/local.js';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const print = (doc) => process.stdout.write(`${JSON.stringify(doc, null, 2)}\n`);

const USAGE = `
mcpscan: check an MCP server before you trust it. Reads packages and probes hosted servers;
never installs, extracts to disk, or runs what it inspects.

WHAT TO SCAN
  mcpscan <registry-name>          any official-registry listing, e.g. io.github.owner/server
                                   (npm or PyPI package: read statically; hosted only: probed)
  mcpscan npm:<package>            an npm package
  mcpscan pypi:<package>           a PyPI package (the wheel pip would install)
  mcpscan https://<host>/mcp       a hosted server: lists its tools read-only (never calls one),
                                   pins them, and reports any change on later runs
  mcpscan --installed              every server your agents already trust: Claude Code, Codex,
                                   Claude Desktop, Cursor, Devin, Gemini CLI (--all for details)
  mcpscan --local                  MCP servers listening on this machine: every listening port,
                                   checked for network exposure, sign-in and Origin validation
  mcpscan --local --subnet <cidr>  the same across a private network range you own (at most a /24)

OUTPUT
  (default)                        readable report with file:line evidence
  --json                           machine-readable, schema mcpscan/v1 (docs/schema-v1.md)
  --sarif                          SARIF 2.1.0 for GitHub code scanning and security dashboards
  --registry-meta                  a _meta block a registry or marketplace can attach to a listing
  --egress                         the hosts its code names, as a starting allowlist for an egress proxy
  --fail-on <level>                exit 1 at or above high|medium|low|info, or never (default high)

OPTIONS
  --version-of <v>                 scan a specific version instead of the latest
  --deps                           also read the vendor's own dependencies (one level, bounded)
  --no-osv                         skip the known-vulnerability lookup on OSV.dev
  --no-cache                       do not read or write the local download cache
  --remote                         with --installed, also probe the hosted servers
  --auth-from-env                  send \${VAR} headers from your environment when probing
  --header 'Name: \${VAR}'          add a header to a probe; the value is read from the environment
  --update-pins                    accept a hosted server's changed tools and re-pin them
  --semantic=agent / --answers f   let the agent running you judge tool descriptions (no API key)

LEARN
  mcpscan explain                  every check, one line each
  mcpscan explain <check>          what a finding means, why it matters, what to do

WHAT LEAVES YOUR MACHINE
  Public package names and versions (npm or PyPI, the MCP registry, OSV.dev). A probe contacts
  the server you name. No scan result, config, key or tool description is ever sent anywhere.

EXAMPLES
  mcpscan npm:@modelcontextprotocol/server-filesystem
  mcpscan pypi:mcp-server-fetch
  mcpscan io.github.owner/my-server --sarif > mcpscan.sarif
  mcpscan explain undeclared-env
`;

function parseArgs(argv) {
  const args = { target: null, json: false, sarif: false, registryMeta: false, egress: false, local: false, subnet: null, failOn: 'high', version: 'latest', semantic: false, installed: false, all: false, deps: false, osv: true, agentRequest: false, answers: null, remote: false, authFromEnv: false, updatePins: false, headers: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--sarif') args.sarif = true;
    else if (a === '--registry-meta') args.registryMeta = true;
    else if (a === '--egress') args.egress = true;
    else if (a === '--local') args.local = true;
    else if (a === '--subnet') args.subnet = argv[++i];
    else if (a === '--semantic') args.semantic = true;
    else if (a === '--semantic=agent') args.agentRequest = true;
    else if (a === '--answers') args.answers = argv[++i];
    else if (a === '--remote') args.remote = true;
    else if (a === '--auth-from-env') args.authFromEnv = true;
    else if (a === '--update-pins') args.updatePins = true;
    else if (a === '--header') {
      const [k, ...v] = String(argv[++i] ?? '').split(':');
      if (k && v.length) args.headers[k.trim()] = v.join(':').trim();
    }
    else if (a === '--installed') args.installed = true;
    else if (a === '--all') args.all = true;
    else if (a === '--deps') args.deps = true;
    else if (a === '--no-osv') args.osv = false;
    else if (a === '--no-cache') process.env.MCPSCAN_NO_CACHE = '1';
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--version-of') args.version = argv[++i];
    else if (a === '-h' || a === '--help') args.help = true;
    else if (!a.startsWith('-')) args.target ??= a;
  }
  return args;
}

if (process.argv[2] === 'explain') {
  const { text, found } = explain(process.argv[3]);
  process.stdout.write(`${text}\n`);
  process.exit(found ? 0 : 2);
}

const args = parseArgs(process.argv.slice(2));

if (args.target && /^https?:\/\//i.test(args.target)) {
  try {
    const { headers, missing } = resolveHeaderRefs(args.headers);
    if (missing.length) process.stderr.write(`mcpscan: not set in this environment: ${missing.join(', ')}\n`);
    const result = await scanRemote(args.target, { headers, updatePins: args.updatePins });
    if (args.sarif) print(await scanToSarif([result], { version: VERSION }));
    else if (args.registryMeta) print(await toRegistryMeta(result, { version: VERSION }));
    else if (args.json) print(await toJsonV1(result, { version: VERSION }));
    else process.stdout.write(`${renderRemote(result)}\n`);
    process.exit(args.failOn === 'never' ? 0 : exitCode(result.findings, { failOn: args.failOn }));
  } catch (err) {
    process.stderr.write(`mcpscan: ${err.message}\n`);
    process.exit(2);
  }
}

if (args.agentRequest && args.target) {
  // Step 1: the agent protocol. Machine-readable only: this output is for an agent.
  try {
    const r = await scan(args.target, { version: args.version, deps: args.deps, osv: false });
    const built = buildDisclosureRequest({ pkg: r.pkg, entry: r.entry, findings: r.findings });
    const out = built.skip
      ? { format: 'mcpscan-judgment-request/1', target: args.target, skip: built.skip.disclosure.reason }
      : buildAgentRequest({ target: args.target, pkg: r.pkg, request: built.request, options: { deps: args.deps } });
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    process.exit(0);
  } catch (err) {
    process.stderr.write(`mcpscan: ${err.message}\n`);
    process.exit(2);
  }
}

if (args.answers) {
  // Step 2: re-scan exactly what was judged, then apply the answers.
  try {
    const doc = JSON.parse(readFileSync(args.answers, 'utf8'));
    const judge = createAgentJudge(doc);
    const result = await scan(doc.target, {
      version: doc.version,
      deps: Boolean(doc.options?.deps),
      semantic: true,
      judge,
      osv: args.osv,
    });
    if (args.sarif) print(await scanToSarif([result], { version: VERSION }));
    else if (args.json) print(await toJsonV1(result, { version: VERSION }));
    else process.stdout.write(`${render(result)}\n`);
    process.exit(args.failOn === 'never' ? 0 : exitCode(result.findings, { failOn: args.failOn }));
  } catch (err) {
    process.stderr.write(`mcpscan: ${err.message}\n`);
    process.exit(2);
  }
}

if (args.local && !args.help) {
  try {
    const result = await scanLocal({ subnet: args.subnet ?? undefined });
    if (args.sarif) print(await scanToSarif(result.servers.map((s) => ({ target: s.target, pkg: null, findings: s.findings })), { version: VERSION }));
    else if (args.json) print({ schema: 'mcpscan/v1', tool: { name: 'mcpscan', version: VERSION }, ...result });
    else process.stdout.write(`${renderLocal(result)}\n`);
    const all = result.servers.flatMap((s) => s.findings);
    process.exit(args.failOn === 'never' ? 0 : exitCode(all, { failOn: args.failOn }));
  } catch (err) {
    process.stderr.write(`mcpscan: ${err.message}\n`);
    process.exit(2);
  }
}

if (args.installed && !args.help) {
  try {
    const result = await auditInstalled({ semantic: args.semantic, deps: args.deps, osv: args.osv, remote: args.remote, authFromEnv: args.authFromEnv, updatePins: args.updatePins });
    if (args.sarif) print(await scanToSarif(result.servers.map((s) => ({ target: `${s.agent}:${s.name}`, pkg: null, findings: s.findings })), { version: VERSION }));
    else if (args.json) print(await installedToJsonV1(result, { version: VERSION }));
    else process.stdout.write(`${renderInstalled(result, { all: args.all })}\n`);
    const all = result.servers.flatMap((s) => s.findings);
    process.exit(args.failOn === 'never' ? 0 : exitCode(all, { failOn: args.failOn }));
  } catch (err) {
    process.stderr.write(`mcpscan: ${err.message}\n`);
    process.exit(2);
  }
}

if (args.help || !args.target) {
  process.stdout.write(USAGE);
  process.exit(args.help ? 0 : 2); // --help is a request, not a usage error
}

try {
  const result = await scan(args.target, { version: args.version, semantic: args.semantic, deps: args.deps, osv: args.osv });
  if (args.sarif) print(await scanToSarif([result], { version: VERSION }));
  else if (args.registryMeta) print(await toRegistryMeta(result, { version: VERSION }));
  else if (args.egress) process.stdout.write(egressAllowlist(result));
  else if (args.json) print(await toJsonV1(result, { version: VERSION }));
  else {
    process.stdout.write(`${result.remote ? renderRemote(result) : render(result)}\n`);
  }
  process.exit(args.failOn === 'never' ? 0 : exitCode(result.findings, { failOn: args.failOn }));
} catch (err) {
  process.stderr.write(`mcpscan: ${err.message}\n`);
  process.exit(2);
}
