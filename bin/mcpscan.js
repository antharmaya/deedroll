#!/usr/bin/env node
import { scan } from '../src/index.js';
import { render, renderInstalled, renderRemote, exitCode } from '../src/report.js';
import { scanRemote } from '../src/index.js';
import { resolveHeaderRefs } from '../src/remote.js';
import { auditInstalled } from '../src/audit.js';
import { readFileSync } from 'node:fs';
import { buildDisclosureRequest } from '../src/disclosure.js';
import { buildAgentRequest, createAgentJudge } from '../src/agent-judge.js';

const USAGE = `
mcpscan — static trust scanner for MCP servers

  mcpscan https://<host>/mcp     probe a hosted server read-only (initialize + tools/list only),
                                 pin its tools, and report any change since the last probe
  mcpscan --installed            audit every MCP server your agents already trust
                                 (Claude Code, Codex, Claude Desktop, Cursor, Windsurf, Gemini CLI)
  mcpscan --installed --remote   also probe the hosted ones (--auth-from-env sends \${VAR} headers)
  mcpscan <url> --update-pins    accept the changes found and re-pin
  mcpscan <url> --header 'Name: \${VAR}'   add a header; \${VAR} is read from the environment
  mcpscan <registry-name>        scan a server listed in the official MCP registry
  mcpscan npm:<package>          scan an npm package directly
  mcpscan <target> --json        machine-readable output
  mcpscan <target> --fail-on <high|medium|low|info|never>
  mcpscan <target> --deps        also scan the vendor's own dependencies (thin wrappers keep
                                 their tools there); one level, bounded, costs extra downloads
  mcpscan <target> --no-osv      skip the known-vulnerability lookup (it sends package names and
                                 versions to OSV.dev; nothing else ever leaves the machine)
  mcpscan <target> --no-cache    do not read or write the local tarball cache
  mcpscan <target> --semantic=agent   print a judgment request for the agent running you to answer
                                      (no API key; see the mcpscan skill)
  mcpscan --answers <file.json>       apply an agent's answers to that request and report
  mcpscan <target> --semantic         judge via TypeSafe's API instead (needs TYPESAFE_API_KEY)

It never installs, extracts or executes what it inspects: the tarball is read in memory.

Examples
  mcpscan npm:@modelcontextprotocol/server-filesystem
  mcpscan io.github.owner/my-server --json
`;

function parseArgs(argv) {
  const args = { target: null, json: false, failOn: 'high', version: 'latest', semantic: false, installed: false, all: false, deps: false, osv: true, agentRequest: false, answers: null, remote: false, authFromEnv: false, updatePins: false, headers: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
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

const args = parseArgs(process.argv.slice(2));

if (args.target && /^https?:\/\//i.test(args.target)) {
  try {
    const { headers, missing } = resolveHeaderRefs(args.headers);
    if (missing.length) process.stderr.write(`mcpscan: not set in this environment: ${missing.join(', ')}\n`);
    const result = await scanRemote(args.target, { headers, updatePins: args.updatePins });
    if (args.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
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
    if (args.json) process.stdout.write(`${JSON.stringify({ target: result.target, disclosure: result.disclosure, findings: result.findings }, null, 2)}\n`);
    else process.stdout.write(`${render(result)}\n`);
    process.exit(args.failOn === 'never' ? 0 : exitCode(result.findings, { failOn: args.failOn }));
  } catch (err) {
    process.stderr.write(`mcpscan: ${err.message}\n`);
    process.exit(2);
  }
}

if (args.installed && !args.help) {
  try {
    const result = await auditInstalled({ semantic: args.semantic, deps: args.deps, osv: args.osv, remote: args.remote, authFromEnv: args.authFromEnv, updatePins: args.updatePins });
    if (args.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
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
  if (args.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          target: result.target,
          package: result.pkg ? { name: result.pkg.name, version: result.pkg.version, sha256: result.pkg.sha256 } : null,
          inRegistry: Boolean(result.entry),
          declaredEnv: [...(result.declared?.keys() ?? [])],
          findings: result.findings,
          ...(result.disclosure ? { disclosure: result.disclosure } : {}),
        },
        null,
        2
      )}\n`
    );
  } else {
    process.stdout.write(`${render(result)}\n`);
  }
  process.exit(args.failOn === 'never' ? 0 : exitCode(result.findings, { failOn: args.failOn }));
} catch (err) {
  process.stderr.write(`mcpscan: ${err.message}\n`);
  process.exit(2);
}
