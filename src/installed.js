/**
 * `--installed`: find every MCP server the user's agents already trust, without
 * launching any of them. Parsing (and the rule that secret values are dropped at the
 * parser) lives in installed-core.js, shared with the browser page.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseCodexToml, parseJsonServers } from './installed-core.js';

export { resolveLaunch, parseCodexToml, parseJsonServers, configFindings, parseConfigText, originForFile } from './installed-core.js';

/** Where each agent keeps its MCP config. JSON ones share the `mcpServers` shape. */
function configLocations(home, cwd) {
  return [
    { agent: 'claude-code', file: join(home, '.claude.json'), format: 'claude-json' },
    { agent: 'claude-code', file: join(cwd, '.mcp.json'), format: 'mcp-json', scope: 'project' },
    { agent: 'codex', file: join(home, '.codex', 'config.toml'), format: 'codex-toml' },
    { agent: 'claude-desktop', file: join(home, '.config', 'Claude', 'claude_desktop_config.json'), format: 'mcp-json' },
    { agent: 'claude-desktop', file: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), format: 'mcp-json' },
    { agent: 'cursor', file: join(home, '.cursor', 'mcp.json'), format: 'mcp-json' },
    // Windsurf was renamed Devin; the config still lives at the old path.
    { agent: 'devin', file: join(home, '.codeium', 'windsurf', 'mcp_config.json'), format: 'mcp-json' },
    { agent: 'gemini-cli', file: join(home, '.gemini', 'settings.json'), format: 'mcp-json' },
  ];
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

