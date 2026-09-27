/**
 * Find the tools an MCP server declares, and the descriptions a user reads before
 * trusting them. Static and best-effort: descriptions built at runtime, or held in a
 * variable, are not found. Callers must treat "no tools found" as "not judged", never
 * as "nothing to disclose".
 */

/** A string literal in ', " or ` quotes, capturing quote as group n and body as n+1. */
const STR = (n) => `(['"\`])((?:\\\\.|(?!\\${n})[^\\\\])*?)\\${n}`;

const PATTERNS = [
  // server.tool("name", "description", ...) — the McpServer convenience API
  { re: new RegExp(`\\.tool\\(\\s*${STR(1)}\\s*,\\s*${STR(3)}`, 'g'), name: 2, desc: 4 },
  // server.registerTool("name", { title, description, ... }, handler)
  {
    // Same rule as the tools-array pattern below: never cross the config object's closing brace.
    re: new RegExp(`registerTool\\(\\s*${STR(1)}\\s*,\\s*\\{(?:[^{}]|\\{[^{}]*\\})*?\\bdescription\\s*:\\s*${STR(3)}`, 'g'),
    name: 2,
    desc: 4,
  },
  // { name: "x", description: "y" } — ListTools handlers returning a tools array.
  // The gap may hold one level of nested braces (an inputSchema) but may never cross
  // the object's own closing brace: otherwise `new McpServer({ name: "srv" })` borrows
  // the next tool's description and becomes a phantom tool. Seen live in pretrip-mcp.
  {
    re: new RegExp(`\\bname\\s*:\\s*${STR(1)}\\s*,(?:[^{}]|\\{[^{}]*\\})*?\\bdescription\\s*:\\s*${STR(3)}`, 'g'),
    name: 2,
    desc: 4,
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

const TOOL_NAME = /^[A-Za-z][\w.-]{0,63}$/;
const CODE_FILE = /\.(m?js|cjs|ts|mts|cts|py)$/i;
const MAX_DESCRIPTION = 600;
const MAX_TOOLS = 80;

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
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

    for (const { re, name: ni, desc: di } of PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const name = m[ni];
        const description = (m[di] ?? '').replace(/\s+/g, ' ').trim();
        if (!TOOL_NAME.test(name) || description.length === 0) continue;
        if (byName.has(name)) continue; // src and dist often both ship; first wins
        byName.set(name, {
          name,
          description: description.slice(0, MAX_DESCRIPTION),
          file: path,
          line: lineOf(text, m.index),
        });
      }
    }
  }

  const tools = [...byName.values()];
  return { tools: tools.slice(0, MAX_TOOLS), truncated: tools.length > MAX_TOOLS };
}
