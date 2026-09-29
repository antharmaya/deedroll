/**
 * Tool-name collisions across the servers your agents already trust.
 *
 * A client resolves a tool call by name. When two DIFFERENT servers both offer a tool
 * called, say, "search", whichever the client's runtime happens to route to can stand in
 * for the other — silently, with no error. This is what the NSA's May 2026 MCP guidance
 * calls "tool invocation path confusion": a malicious or compromised server registers a
 * name a trusted server already uses, and hijacks calls meant for it.
 *
 * Pure and platform-neutral: called from the CLI's --installed (with tool names read from
 * package code and from hosted probes) and, wherever the page already has tool lists for
 * two or more servers, from the browser's config audit too.
 */

/**
 * @param {Array<{key: string, label: string, tools: string[]}>} installs
 *   One entry per DISTINCT installation (not per config file: the same package named by
 *   two agents is one install). `key` identifies it; `label` is what to show a person.
 * @returns {Array<{name: string, keys: string[]}>} every tool name offered by more than
 *   one distinct install, with the keys of the installs that offer it.
 */
export function detectToolCollisions(installs) {
  const byName = new Map();
  for (const inst of installs) {
    for (const name of new Set(inst.tools ?? [])) {
      if (!byName.has(name)) byName.set(name, new Set());
      byName.get(name).add(inst.key);
    }
  }
  const out = [];
  for (const [name, keys] of byName) if (keys.size > 1) out.push({ name, keys: [...keys] });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * One finding per colliding tool name, addressed to one install (naming the others it
 * collides with). Called once per install that appears in `collisions`.
 */
export function collisionFindings(collisions, install, labelOf) {
  const mine = collisions.filter((c) => c.keys.includes(install.key));
  return mine.map((c) => {
    const others = c.keys.filter((k) => k !== install.key).map(labelOf);
    return {
      check: 'tool-name-collision',
      subject: c.name,
      severity: 'medium',
      message: `also offers a tool named "${c.name}", same as ${others.join(' and ')}; a client resolves tools by name, so either could silently answer a call meant for the other`,
      evidence: [{ file: install.label, line: 0, text: `"${c.name}" also offered by: ${others.join(', ')}` }],
    };
  });
}
