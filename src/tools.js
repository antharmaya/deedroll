/**
 * Find the tools an MCP server declares, and the descriptions a user reads before
 * trusting them. Static and best-effort: a name or description held in a same-file
 * `const` is resolved; anything built at runtime, imported from another file, or read
 * off an object (`config.description`) is not. Callers must treat "no tools found" as
 * "not judged", never as "nothing to disclose".
 */

/** A string literal in ', " or ` quotes, capturing quote as group n and body as n+1. */
const STR = (n) => `(['"\`])((?:\\\\.|(?!\\${n})[^\\\\])*?)\\${n}`;

/**
 * A literal OR a bare identifier: quote n, body n+1, identifier n+2.
 * The lookahead refuses member access and calls (`config.description`, `z.string()`,
 * `x[0]`): those are runtime values, and guessing at them would invent descriptions.
 */
const VALUE = (n) => `(?:${STR(n)}|([A-Za-z_$][\\w$]*)(?![\\w$.(\\[]))`;

/** The body of an object literal, allowing one nested level, never crossing its own `}`. */
const GAP = `(?:[^{}]|\\{[^{}]*\\})*?`;

const PATTERNS = [
  // server.tool(name, description, ...) — the McpServer convenience API
  {
    re: new RegExp(`\\.tool\\(\\s*${VALUE(1)}\\s*,\\s*${VALUE(4)}`, 'g'),
    name: { lit: 2, id: 3 },
    desc: { lit: 5, id: 6 },
    descLast: true,
  },
  // Any tool-registering call: registerTool(name, {...}), and vendor wrappers such as
  // registerDatabaseTool(server, 'x', {...}) (Pinecone) or defineTool('x', {...}).
  // One optional leading argument (the server) is allowed. Tooltip helpers are excluded.
  {
    re: new RegExp(
      `\\b(?![\\w$]*[Tt]ooltip)[\\w$]*[Tt]ool[\\w$]*\\(\\s*(?:[\\w$.]+\\s*,\\s*)?${VALUE(1)}\\s*,\\s*\\{${GAP}\\bdescription\\s*:\\s*${VALUE(4)}`,
      'g'
    ),
    name: { lit: 2, id: 3 },
    desc: { lit: 5, id: 6 },
    descLast: true,
  },
  // { name: "x", description: "y" } — ListTools handlers returning a tools array.
  // GAP never crosses the object's own closing brace: otherwise `new McpServer({ name:
  // "srv" })` borrows the next tool's description and becomes a phantom tool (pretrip-mcp).
  {
    re: new RegExp(`\\bname\\s*:\\s*${STR(1)}\\s*,${GAP}\\bdescription\\s*:\\s*${VALUE(3)}`, 'g'),
    name: 2,
    desc: { lit: 4, id: 5 },
    descLast: true,
  },
  // Python: @mcp.tool(description="...") def name(
  {
    re: new RegExp(`@[\\w.]+\\.tool\\([^)]*?description\\s*=\\s*${STR(1)}[^)]*\\)\\s*(?:async\\s+)?def\\s+(\\w+)`, 'g'),
    name: 3,
    desc: 2,
  },
  // Python: @mcp.tool() def name(...): """docstring"""
  {
    re: /@[\w.]+\.tool\([^)]*\)\s*(?:async\s+)?def\s+(\w+)\s*\([\s\S]*?\)\s*(?:->\s*[^:\n]+)?:\s*[rRuU]?("""|''')([\s\S]*?)\2/g,
    name: 1,
    desc: 3,
  },
];

/** `const X = "..."` / `export const X = \`...\`` whose whole initialiser is a literal. */
const CONST_DEF = new RegExp(`(?:^|[\\s;{}])(?:export\\s+)?(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*${STR(2)}`, 'g');

const TOOL_NAME = /^[A-Za-z][\w.-]{0,63}$/;
const CODE_FILE = /\.(m?js|cjs|ts|mts|cts|py)$/i;
const MAX_DESCRIPTION = 2000; // longer is cut AND marked partial: the cut text could hold the disclosure
const MAX_TOOLS = 80;

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** String constants defined in ONE file. Per file, because INSTRUCTIONS means something different in each. */
function constantsIn(text) {
  const consts = new Map();
  CONST_DEF.lastIndex = 0;
  let m;
  while ((m = CONST_DEF.exec(text)) !== null) {
    if (!consts.has(m[1])) consts.set(m[1], m[3]);
  }
  return consts;
}

/** Read a captured value: a literal body, or a same-file constant, or nothing. */
function pick(m, spec, consts) {
  if (typeof spec === 'number') return m[spec];
  if (m[spec.lit] !== undefined) return m[spec.lit];
  if (m[spec.id] !== undefined) return consts.get(m[spec.id]) ?? null;
  return null;
}

const STR_AT = new RegExp(STR(1), 'y');
const IDENT_AT = /([A-Za-z_$][\w$]*)/y;

/**
 * Follow `+ 'text' + CONST + ...` after a description. Every piece must be a literal or
 * a same-file constant; the first piece that is not makes the result partial. Found
 * live in @adeu/mcp-server: `description: COMMON_DESC + OPERATIONS_DESC` was read as
 * its first half only, which could make a disclosed capability look undisclosed.
 */
function followConcat(text, from, consts) {
  let i = from;
  let extra = '';
  for (let pieces = 0; pieces < 12; pieces++) {
    const plus = /\s*\+\s*/y;
    plus.lastIndex = i;
    if (!plus.exec(text)) return { extra, partial: false };
    i = plus.lastIndex;

    STR_AT.lastIndex = i;
    const lit = STR_AT.exec(text);
    if (lit) {
      extra += lit[2];
      i = STR_AT.lastIndex;
      continue;
    }
    IDENT_AT.lastIndex = i;
    const id = IDENT_AT.exec(text);
    if (!id || /[\w$.(\[]/.test(text[IDENT_AT.lastIndex] ?? '') || !consts.has(id[1])) {
      return { extra, partial: true };
    }
    extra += consts.get(id[1]);
    i = IDENT_AT.lastIndex;
  }
  return { extra, partial: true }; // absurdly long chain: do not pretend it is whole
}

/**
 * @param {Map<string, Buffer>} files
 * @returns {{tools: Array<{name, description, file, line}>, truncated: boolean}}
 */
export function extractTools(files) {
  const byName = new Map();

  for (const [path, buf] of files) {
    if (!CODE_FILE.test(path) || path.endsWith('.d.ts')) continue;
    const text = buf.toString('utf8');
    if (text.includes('\0')) continue;
    const consts = constantsIn(text);

    for (const { re, name: ns, desc: ds, descLast } of PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const name = pick(m, ns, consts);
        let raw = pick(m, ds, consts) ?? '';
        let partial = false;
        if (descLast && raw) {
          const tail = followConcat(text, m.index + m[0].length, consts);
          raw += tail.extra;
          partial = tail.partial;
        }
        const description = raw.replace(/\s+/g, ' ').trim();
        if (!name || !TOOL_NAME.test(name) || description.length === 0) continue;
        if (byName.has(name)) continue; // src and dist often both ship; first wins
        byName.set(name, {
          name,
          description: description.slice(0, MAX_DESCRIPTION),
          file: path,
          line: lineOf(text, m.index),
          ...(partial || description.length > MAX_DESCRIPTION ? { partial: true } : {}),
        });
      }
    }
  }

  const tools = [...byName.values()];
  return { tools: tools.slice(0, MAX_TOOLS), truncated: tools.length > MAX_TOOLS };
}
