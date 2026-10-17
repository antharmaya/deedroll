/**
 * The registry band's sentences, from data only. One module for both places they appear: the
 * page (web/app.js, from the live /api/servers and /history/) and the no-JS fallback that
 * scripts/build-site.js writes into index.html from the archive on disk. Pure, no DOM.
 */

const n = (x) => Number(x).toLocaleString('en');
/** "14 Oct 2026", in UTC: the record names each day by its UTC date. */
export const day = (iso) => new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
const time = (iso) => new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' });
const days = (k) => `${n(k)} ${k === 1 ? 'day' : 'days'}`;

/** One decimal, truncated, never rounded up: 1,400 of 15,110 is 9.2%, not 9.3%. */
export const pctDown = (k, total) => (total ? (Math.floor((k * 1000) / total) / 10).toFixed(1) : '0.0');

/** The headline: the latest chain entry, and that day's diff when there is one. */
export function recordText(last, chainLength, diff) {
  return {
    figure: n(last.listings),
    when: `From the registry record of ${day(last.date)}, chained to ${days(chainLength - 1)} before it.`,
    added: diff ? n(diff.added.length) : null,
    declared: diff ? n(diff.declarations.length) : null,
    moved: diff ? n(diff.endpoints.length) : null,
  };
}

/** The credential census (scripts/ledger-views.js counts it; this only words it). */
export function censusText(c, builtAt) {
  const left = [
    c.failed ? `${n(c.failed)} whose package could not be read${c.missing ? ` (${n(c.missing)} name a package or version that does not exist)` : ''}` : '',
    c.notScanned ? `${n(c.notScanned)} not scanned yet` : '',
    c.otherOnly ? `${n(c.otherOnly)} that ship only container images, MCPB bundles, NuGet or Cargo packages, which deedroll does not read yet` : '',
  ].filter(Boolean);
  return {
    pct: `${pctDown(c.undeclared, c.scanned)}%`,
    line: `${n(c.undeclared)} of the ${n(c.scanned)} servers with an npm or PyPI package scanned by ${day(c.date)} read a credential their listing and README never mention.`,
    more: `Another ${n(c.readmeOnly)} (${pctDown(c.readmeOnly, c.scanned)}%) explain it only in their README, not the listing that catalogs and agents read.${left.length ? ` Not counted: ${left.join('; ')}.` : ''}`,
    built: builtAt ? `Ledger last built ${day(builtAt)}, ${time(builtAt)} UTC.` : '',
  };
}

/** The first, sampled measurement (web/data/registry-health.json), kept as history. */
export function sampleText(h) {
  return {
    summary: `The first measurement, before every package was scanned: ${h.flagged} mentioned a credential nowhere; ${h.readmeOnly ?? 0} explained it only in their README.`,
    method: `A random sample of npm-published servers in the official MCP registry, ${day(h.sampledAt)}. At 95% confidence it pointed to between ${h.interval[0]}% and ${h.interval[1]}% across the registry; the full count above supersedes it.`,
  };
}
