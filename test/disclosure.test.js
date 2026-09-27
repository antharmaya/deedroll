import test from 'node:test';
import assert from 'node:assert/strict';
import { extractTools } from '../src/tools.js';
import { createTypeSafeJudge, JudgeConfigError } from '../src/judge.js';
import { checkDisclosure, DEFAULT_THRESHOLDS } from '../src/disclosure.js';

const files = (obj) => new Map(Object.entries(obj).map(([k, v]) => [k, Buffer.from(v, 'utf8')]));

// ---------- extraction ----------

test('extracts server.tool(name, description)', () => {
  const { tools } = extractTools(files({ 'index.js': 'server.tool("read_file", "Read a file from disk", schema, h);' }));
  assert.deepEqual(tools.map((t) => [t.name, t.description]), [['read_file', 'Read a file from disk']]);
  assert.equal(tools[0].line, 1);
});

test('extracts registerTool(name, { description })', () => {
  const src = `server.registerTool('search', {\n  title: 'Search',\n  description: 'Search the web for pages',\n  inputSchema: {}\n}, h);`;
  const { tools } = extractTools(files({ 'index.js': src }));
  assert.equal(tools[0].name, 'search');
  assert.equal(tools[0].description, 'Search the web for pages');
});

test('extracts a ListTools array of { name, description }', () => {
  const src = `return { tools: [\n  { name: "list_dir", description: "List a directory" },\n  { name: "stat", description: "File metadata" }\n] };`;
  const { tools } = extractTools(files({ 'server.js': src }));
  assert.deepEqual(tools.map((t) => t.name), ['list_dir', 'stat']);
});

test('extracts python @mcp.tool() docstrings and description kwargs', () => {
  const src = [
    '@mcp.tool()',
    'async def fetch_page(url: str) -> str:',
    '    """Fetch a web page and return its text."""',
    '',
    '@mcp.tool(description="Delete a note")',
    'def delete_note(id):',
    '    pass',
  ].join('\n');
  const { tools } = extractTools(files({ 'server.py': src }));
  const byName = Object.fromEntries(tools.map((t) => [t.name, t.description]));
  assert.equal(byName.fetch_page, 'Fetch a web page and return its text.');
  assert.equal(byName.delete_note, 'Delete a note');
});

test('dedupes a tool shipped in both src and dist', () => {
  const { tools } = extractTools(
    files({ 'src/a.ts': 'server.tool("x", "one", s, h)', 'dist/a.js': 'server.tool("x", "one", s, h)' })
  );
  assert.equal(tools.length, 1);
});

// ---------- judge (TypeSafe wire contract) ----------

function fakeFetch(responses, seen) {
  let i = 0;
  return async (url, init) => {
    seen.push({ url, init, body: JSON.parse(init.body) });
    const r = responses[Math.min(i++, responses.length - 1)];
    return {
      ok: r.status === 200,
      status: r.status,
      json: async () => r.body,
      text: async () => JSON.stringify(r.body ?? ''),
    };
  };
}

const Q = { q1: { type: 'noul', instructions: 'Is it?' } };
const OK = { status: 200, body: { model: 'jev-1.13.0', answers: { q1: { type: 'noul', noul: 0.9 } }, usage: {} } };

test('judge sends the documented request shape', async () => {
  const seen = [];
  const judge = createTypeSafeJudge({ apiKey: 'k', fetchImpl: fakeFetch([OK], seen) });
  const out = await judge.ask({ a: 1 }, Q);
  assert.equal(out.answers.q1.noul, 0.9);
  assert.equal(seen[0].url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(seen[0].init.headers.authorization, 'Bearer k');
  assert.deepEqual(seen[0].body, { state: { a: 1 }, model: 'jev-latest', questions: Q });
});

test('judge retries 429 and 529 with backoff, then succeeds', async () => {
  const seen = [];
  const sleeps = [];
  const judge = createTypeSafeJudge({
    apiKey: 'k',
    fetchImpl: fakeFetch([{ status: 429 }, { status: 529 }, OK], seen),
    sleep: async (ms) => sleeps.push(ms),
  });
  await judge.ask({}, Q);
  assert.equal(seen.length, 3);
  assert.equal(sleeps.length, 2);
  assert.ok(sleeps[1] >= sleeps[0], 'backoff grows');
});

test('judge surfaces a rejected key as a config error, without retrying', async () => {
  const seen = [];
  const judge = createTypeSafeJudge({ apiKey: 'bad', fetchImpl: fakeFetch([{ status: 401 }], seen) });
  await assert.rejects(judge.ask({}, Q), JudgeConfigError);
  assert.equal(seen.length, 1);
});

test('judge refuses to start without a key', () => {
  const saved = process.env.TYPESAFE_API_KEY;
  delete process.env.TYPESAFE_API_KEY;
  try {
    assert.throws(() => createTypeSafeJudge(), JudgeConfigError);
  } finally {
    if (saved !== undefined) process.env.TYPESAFE_API_KEY = saved;
  }
});

test('an incomplete response is an error, never a silent zero', async () => {
  const partial = { status: 200, body: { model: 'jev', answers: {}, usage: {} } };
  const judge = createTypeSafeJudge({ apiKey: 'k', fetchImpl: fakeFetch([partial], []) });
  await assert.rejects(judge.ask({}, Q), /missing a noul answer/);
});

// ---------- disclosure mapping ----------

function staticJudge(values, calls = []) {
  return {
    name: 'static',
    async ask(state, questions) {
      calls.push({ state, questions });
      const answers = {};
      for (const id of Object.keys(questions)) answers[id] = { type: 'noul', noul: values[id] ?? 0.5 };
      return { model: 'static-test', answers, usage: {} };
    },
  };
}

const pkg = {
  name: 'demo',
  manifest: { description: 'A demo server' },
  files: files({ 'index.js': 'server.tool("read_file", "Read a file", s, h);' }),
};
const capabilityFinding = (label) => ({
  check: 'capability',
  severity: 'info',
  message: `uses ${label}`,
  evidence: [{ file: 'index.js', line: 9, text: 'exec(cmd)' }],
});

test('low probability becomes an undisclosed-capability finding with code evidence', async () => {
  const { findings, disclosure } = await checkDisclosure({
    pkg,
    entry: null,
    findings: [capabilityFinding('process execution')],
    judge: staticJudge({ discloses_process_execution: 0.05 }),
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, 'undisclosed-capability');
  assert.equal(findings[0].severity, 'medium');
  assert.equal(findings[0].evidence[0].line, 9);
  assert.equal(disclosure.judgments['process execution'], 0.05);
});

test('the middle band goes to a human, a clear yes produces nothing', async () => {
  const { findings } = await checkDisclosure({
    pkg,
    entry: null,
    findings: [capabilityFinding('process execution'), capabilityFinding('filesystem writes or deletes')],
    judge: staticJudge({ discloses_process_execution: 0.5, discloses_file_writes: 0.95 }),
  });
  assert.deepEqual(findings.map((f) => f.check), ['disclosure-unclear']);
  assert.equal(findings[0].severity, 'info');
});

test('only asks about capabilities that are present, and puts no code in the state', async () => {
  const calls = [];
  await checkDisclosure({
    pkg,
    entry: null,
    findings: [capabilityFinding('filesystem writes or deletes')],
    judge: staticJudge({}, calls),
  });
  assert.deepEqual(Object.keys(calls[0].questions), ['discloses_file_writes']);
  assert.deepEqual(Object.keys(calls[0].state), ['server', 'tools']);
  assert.ok(!JSON.stringify(calls[0].state).includes('exec(cmd)'), 'code evidence must not leak into the state');
});

test('python exec maps to the same question as JS exec', async () => {
  const calls = [];
  await checkDisclosure({
    pkg,
    entry: null,
    findings: [capabilityFinding('process execution'), capabilityFinding('process execution (python)')],
    judge: staticJudge({}, calls),
  });
  assert.deepEqual(Object.keys(calls[0].questions), ['discloses_process_execution']);
});

test('no capabilities means no API call at all', async () => {
  const calls = [];
  const { findings } = await checkDisclosure({ pkg, entry: null, findings: [], judge: staticJudge({}, calls) });
  assert.equal(calls.length, 0);
  assert.deepEqual(findings, []);
});

test('no tool descriptions is reported as not judged, never as clean', async () => {
  const calls = [];
  const { findings, disclosure } = await checkDisclosure({
    pkg: { ...pkg, files: files({ 'index.js': 'const x = 1;' }) },
    entry: null,
    findings: [capabilityFinding('process execution')],
    judge: staticJudge({}, calls),
  });
  assert.equal(calls.length, 0);
  assert.equal(findings[0].check, 'disclosure-not-judged');
  assert.equal(disclosure.judged, false);
});

test('thresholds default to the documented three-way split', () => {
  assert.deepEqual(DEFAULT_THRESHOLDS, { yes: 0.8, no: 0.2 });
});

test('a server constructor name never becomes a phantom tool (regression: pretrip-mcp)', () => {
  const src = [
    'const server = new McpServer({ name: "pretrip", version: "1.0.0" });',
    '',
    'server.registerTool(',
    '  "scan_content",',
    '  {',
    '    title: "Scan",',
    '    description: "Screen marketing copy",',
    '  }, h);',
  ].join('\n');
  const { tools } = extractTools(files({ 'index.mjs': src }));
  assert.deepEqual(tools.map((t) => t.name), ['scan_content']);
});

test('a tools-array entry with a nested inputSchema before its description still matches', () => {
  const src = '{ name: "grep", inputSchema: { type: "object" }, description: "Search files" }';
  const { tools } = extractTools(files({ 'index.js': src }));
  assert.deepEqual(tools.map((t) => [t.name, t.description]), [['grep', 'Search files']]);
});

test('a registerTool without a description does not borrow the next tool\'s', () => {
  const src = [
    'server.registerTool("no_desc", { title: "Untitled" }, h1);',
    'server.registerTool("has_desc", { description: "Does a thing" }, h2);',
  ].join('\n');
  const { tools } = extractTools(files({ 'index.js': src }));
  assert.deepEqual(tools.map((t) => [t.name, t.description]), [['has_desc', 'Does a thing']]);
});
