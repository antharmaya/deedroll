/**
 * The output contract. Pure: no I/O, shared by the CLI, the browser page and the SARIF
 * writer.
 *
 * Check ids are a public API from v1: CI configs, suppressions and dashboards key on
 * them. An id is never renamed or reused; a retired check keeps its entry, marked so.
 * Messages are for people and may change wording at any time, so nothing should parse
 * them (the web page did, which is how a wording change broke a test on 2026-09-28).
 */

export const SCHEMA = 'mcpscan/v1';
export const SCHEMA_URL = 'https://github.com/varbees/mcpscan/blob/main/docs/schema-v1.md';

/** id -> title, why it matters, what to do. Severities vary per finding; `level` is the usual one. */
export const RULES = {
  'undeclared-env': { title: 'Reads a setting its listing does not declare', level: 'high', why: 'The registry listing is what people read before installing; a credential the code reads but the listing never mentions is access nobody agreed to.', fix: 'Declare every environment variable in the server.json listing, marking credentials isSecret.' },
  'dynamic-env': { title: 'Builds an environment variable name at runtime', level: 'info', why: 'A computed name cannot be checked statically, so what it reads is unknown until it runs.', fix: 'Read variables by literal name where possible.' },
  'install-script': { title: 'Runs code when installed', level: 'high', why: 'Install-time code runs with the installing user\'s rights before anyone has used, or reviewed, the server: the classic supply-chain entry point.', fix: 'Remove install-time scripts; publish a wheel for Python packages.' },
  'network-egress': { title: 'Contacts an external host', level: 'info', why: 'Every host in the code is somewhere data can go. Hosts the listing names are expected; others are worth a look.', fix: 'Name the hosts the server talks to in its listing or README.' },
  capability: { title: 'Has a powerful capability', level: 'info', why: 'Running programs, evaluating code, or writing files decides how much damage a compromised or misled server can do.', fix: 'Say so in the tool descriptions; scope it as narrowly as possible.' },
  provenance: { title: 'Cannot be traced to its source', level: 'medium', why: 'Without a linked repository, an integrity match or a history, nothing ties the published code to code anyone reviewed.', fix: 'Link the source repository and publish from CI with provenance.' },
  'provenance-dropped': { title: 'Stopped publishing with provenance', level: 'medium', why: 'Earlier releases were built by CI from a named repository and this one was not: the pattern of a release published from somewhere else, such as a stolen token.', fix: 'Confirm who published this release before installing it.' },
  'publisher-mismatch': { title: 'Built from a different repository than it links to', level: 'medium', why: 'The attestation says where the code was built; the project says where to read it. When they differ, the code you read is not the code you run.', fix: 'Check the repository named in the attestation.' },
  deprecated: { title: 'Deprecated or yanked by its registry', level: 'medium', why: 'The maintainers have withdrawn this version, often for a reason that matters.', fix: 'Move to the version or replacement the notice names.' },
  typosquat: { title: 'Named like an official server', level: 'high', why: 'A near-copy of an official name is how malicious packages get installed by mistake.', fix: 'Install the official package by its exact scoped name.' },
  'instruction-like-text': { title: 'A tool description instructs the AI', level: 'high', why: 'Tool descriptions go straight into the model\'s context. Text that gives it orders, or tells it to hide things from the user, is the shape of tool poisoning.', fix: 'Descriptions should describe the tool, never direct the agent.' },
  'known-vulnerability': { title: 'Has a known vulnerability', level: 'high', why: 'A published advisory (OSV.dev, including GitHub advisories) affects this exact version.', fix: 'Upgrade to the fixed version the advisory names.' },
  'vuln-lookup-failed': { title: 'Vulnerability lookup did not complete', level: 'info', why: 'OSV.dev did not answer, so known vulnerabilities were not checked.', fix: 'Run the scan again.' },
  'multiple-listings': { title: 'Several registry listings ship this package', level: 'info', why: 'Different listings can declare different settings for the same code.', fix: 'Check which listing you are installing from.' },
  'no-package': { title: 'Nothing to scan statically', level: 'info', why: 'The listing ships no package this version of mcpscan reads.', fix: 'Probe its remote endpoint instead.' },
  'undisclosed-capability': { title: 'Tool descriptions do not disclose a capability', level: 'medium', why: 'The agent and the user decide what to allow from the descriptions; a capability they never mention is a surprise by design.', fix: 'Describe what each tool can run, write or contact.' },
  'disclosure-unclear': { title: 'Disclosure could not be decided', level: 'info', why: 'The judge could not say whether the descriptions disclose a capability.', fix: 'Read the descriptions yourself.' },
  'disclosure-not-judged': { title: 'Disclosure was not judged', level: 'info', why: 'Descriptions were missing or cut off, so no verdict would be honest.', fix: 'None needed.' },
  'plaintext-secret': { title: 'A secret sits in plain text in an agent config', level: 'medium', why: 'Config files get synced, shared and pasted into bug reports.', fix: 'Reference an environment variable or a file instead.' },
  'credential-unresolved': { title: 'A referenced credential is not set', level: 'info', why: 'The config points at a variable that is not in the environment.', fix: 'Set it, or remove the reference.' },
  'unpinned-launch': { title: 'Launches whatever version is newest', level: 'medium', why: 'npx or uvx without a version runs the latest release at every start, so a bad release reaches you without any action on your part.', fix: 'Pin an exact version in the launch command.' },
  'not-scanned': { title: 'Configured server not scanned', level: 'info', why: 'Its launch method is not one mcpscan reads yet.', fix: 'None needed.' },
  'scan-error': { title: 'The scan failed', level: 'info', why: 'Something went wrong fetching or reading this server.', fix: 'Run it again; report it if it persists.' },
  'remote-not-probed': { title: 'Remote server could not be probed', level: 'info', why: 'It needs sign-in, redirected, or did not answer as MCP, so its tools were not listed.', fix: 'Probe with credentials if you use it.' },
  'tools-truncated': { title: 'Tool list was cut off', level: 'info', why: 'The server returned more tools than the probe reads.', fix: 'None needed.' },
  pinned: { title: 'Tools pinned for the first time', level: 'info', why: 'Later probes will report any change against this snapshot.', fix: 'None needed.' },
  'pins-updated': { title: 'Pins updated', level: 'info', why: 'The current tools were accepted as the new snapshot.', fix: 'None needed.' },
  'tool-description-changed': { title: 'A tool description changed since it was pinned', level: 'high', why: 'A hosted server can rewrite what its tools tell the model at any time, after you approved them: the rug pull.', fix: 'Read the new text; accept it with --update-pins only if it is fine.' },
  'tool-schema-changed': { title: 'A tool\'s inputs changed since it was pinned', level: 'medium', why: 'New parameters can widen what a tool can be asked to do.', fix: 'Review the change, then --update-pins.' },
  'tool-added': { title: 'A tool was added since it was pinned', level: 'medium', why: 'New tools arrive with no approval step in most clients.', fix: 'Review it, then --update-pins.' },
  'tool-removed': { title: 'A tool was removed since it was pinned', level: 'low', why: 'Usually benign; listed so the snapshot stays honest.', fix: 'None needed.' },
};

const NUMBERS = /\d+/g;

/**
 * A stable id for one finding, for baselines and suppressions. Built from what the
 * finding is about, never from line numbers (they move with every edit) or counts that
 * change daily ("published 3 days ago").
 */
export async function fingerprint(f) {
  const about = f.subject ?? (f.check === 'provenance' ? f.message.replace(NUMBERS, '#') : f.message);
  const text = `${f.check}\u0000${about}\u0000${f.evidence?.[0]?.file ?? ''}`;
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return [...hash.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Findings with their fingerprint, ready to serialise. */
export async function withIds(findings) {
  return Promise.all(findings.map(async (f) => ({ id: await fingerprint(f), ...f })));
}
