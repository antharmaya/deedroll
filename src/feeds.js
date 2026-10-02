/**
 * Ways to follow one server's record without an account: a README badge (the shields.io endpoint
 * format) and an Atom feed of its log. Both say only what the ledger observed, in plain words.
 * A badge never says "safe" or "verified": it states how what the code reads compares with what
 * the listing declares, which is the one thing the ledger measures for every packaged server.
 */

const count = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const list = (xs, max = 4) => (xs.length <= max ? xs.join(', ') : `${xs.slice(0, max).join(', ')} and ${xs.length - max} more`);

/** One log entry as a sentence. Shared by the feed and, later, the server pages. */
export function describeEntry(e) {
  switch (e.kind) {
    case 'seen': return `First seen in the official registry${e.version ? ` at version ${e.version}` : ''}.`;
    case 'back': return `Back in the registry${e.version ? ` at version ${e.version}` : ''}.`;
    case 'gone': return 'No longer in the registry.';
    case 'changed': return e.changes.map(describeChange).join(' ');
    case 'scanned': return describeScan(e);
    case 'probe': return describeProbe(e);
    default: return `Recorded: ${e.kind}.`;
  }
}

function describeChange(c) {
  if (c.field === 'version') return `Version ${c.from ?? 'none'} → ${c.to ?? 'none'}.`;
  if (c.field === 'description') return 'Description changed.';
  if (c.field === 'status') return `Status ${c.from ?? 'none'} → ${c.to ?? 'none'}.`;
  return `${c.field} changed.`;
}

function describeScan(e) {
  const what = `${e.package}${e.version ? ` ${e.version}` : ''}`;
  if (e.first) {
    const parts = [];
    if (e.undeclared?.length) parts.push(`its code reads ${count(e.undeclared.length, 'credential')} the listing does not declare and no README mentions (${list(e.undeclared)})`);
    if (e.readmeOnly?.length) parts.push(`${count(e.readmeOnly.length, 'credential')} explained only in the README (${list(e.readmeOnly)})`);
    if (e.install) parts.push(`${count(e.install, 'install script')}`);
    if (e.vulns) parts.push(`${count(e.vulns, 'known vulnerability', 'known vulnerabilities')} in the package`);
    return `Code of ${what} read for the first time${parts.length ? `: ${parts.join('; ')}.` : '. Every credential it reads is declared.'}`;
  }
  const parts = [];
  const set = (k, label) => {
    const d = e[k];
    if (!d) return;
    if (d.added.length) parts.push(`now ${label}: ${list(d.added)}`);
    if (d.removed.length) parts.push(`no longer ${label}: ${list(d.removed)}`);
  };
  set('undeclared', 'reads, undeclared');
  set('readmeOnly', 'explained only in the README');
  set('hosts', 'contacts');
  set('caps', 'uses');
  set('install', 'runs at install');
  set('flags', 'flagged');
  if (e.vulns) parts.push(`known vulnerabilities ${e.vulns.from} → ${e.vulns.to}`);
  if (e.provenance) parts.push(e.provenance.to ? 'now published with provenance' : 'stopped publishing with provenance');
  return `Code of ${what} differs from the previous version: ${parts.join('; ')}.`;
}

function describeProbe(e) {
  const host = (() => { try { return new URL(e.url).host; } catch { return e.url; } })();
  if (e.first) return e.probed ? `Hosted endpoint ${host} answered with ${count(e.tools ?? 0, 'tool')}.` : `Hosted endpoint ${host} could not be read (${e.reason ?? 'no answer'}).`;
  if (e.added || e.removed || e.descriptionChanged || e.inputsChanged) {
    const parts = [];
    if (e.added?.length) parts.push(`tools added: ${list(e.added)}`);
    if (e.removed?.length) parts.push(`tools removed: ${list(e.removed)}`);
    if (e.descriptionChanged?.length) parts.push(`descriptions changed: ${list(e.descriptionChanged)}`);
    if (e.inputsChanged?.length) parts.push(`inputs changed: ${list(e.inputsChanged)}`);
    return `Hosted endpoint ${host}: ${parts.join('; ')}.`;
  }
  return e.probed ? `Hosted endpoint ${host} answers again (${count(e.tools ?? 0, 'tool')}).` : `Hosted endpoint ${host} stopped answering (${e.reason ?? 'no answer'}).`;
}

/**
 * The shields.io endpoint badge for one record (https://shields.io/badges/endpoint-badge).
 * Colours carry no verdict: blue when the code and the listing agree, grey otherwise.
 */
export function badgeOf(record) {
  const base = { schemaVersion: 1, label: 'deedroll', cacheSeconds: 3600 };
  if (!record) return { ...base, message: 'not in the registry', color: 'lightgrey' };
  if (record.gone) return { ...base, message: 'no longer listed', color: 'lightgrey' };
  const sigs = Object.values(record.signals ?? {});
  const scanned = sigs.filter((s) => !s.error);
  if (!scanned.length) {
    if (sigs.some((s) => s.missing)) return { ...base, message: 'package not found', color: 'lightgrey' };
    const hosted = (record.latest?.remotes ?? []).length > 0;
    return { ...base, message: hosted ? 'hosted · on record' : 'on record', color: 'blue' };
  }
  const undeclared = new Set(scanned.flatMap((s) => s.undeclared.map((r) => r.n))).size;
  const readmeOnly = new Set(scanned.flatMap((s) => s.readmeOnly)).size;
  if (undeclared) return { ...base, message: `${count(undeclared, 'credential')} not declared`, color: 'inactive' };
  if (readmeOnly) return { ...base, message: `${count(readmeOnly, 'credential')} in README only`, color: 'inactive' };
  return { ...base, message: 'declares what it reads', color: 'blue' };
}

const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** An Atom feed of one record's log, newest first. `origin` is the site's https origin. */
export function atomFeed(record, origin, limit = 50) {
  const name = record.name;
  const page = `${origin}/web/?q=${encodeURIComponent(name)}`;
  const self = `${origin}/feed/${name}.atom`;
  const entries = record.log.map((e, i) => ({ e, i })).reverse().slice(0, limit);
  const updated = `${(record.log.at(-1)?.date ?? record.firstSeen)}T00:00:00Z`;
  const items = entries.map(({ e, i }) => {
    const text = describeEntry(e);
    const title = text.length > 110 ? `${text.slice(0, 109)}…` : text;
    return `  <entry>
    <id>${xml(`${self}#${i}`)}</id>
    <title>${xml(title)}</title>
    <updated>${e.date}T00:00:00Z</updated>
    <link href="${xml(page)}"/>
    <content type="text">${xml(text)}</content>
  </entry>`;
  }).join('\n');
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${xml(self)}</id>
  <title>${xml(`${name} on deedroll`)}</title>
  <subtitle>What the official MCP registry lists for this server, and what its code does, day by day.</subtitle>
  <link rel="self" href="${xml(self)}"/>
  <link href="${xml(page)}"/>
  <updated>${updated}</updated>
  <author><name>deedroll by Antharmaya Labs</name></author>
${items}
</feed>
`;
}
