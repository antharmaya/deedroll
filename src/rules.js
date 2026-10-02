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
/** Kept equal to package.json's version by a test; the browser cannot read package.json. */
export const TOOL_VERSION = '0.1.0';
export const SCHEMA_URL = 'https://github.com/varbees/mcpscan/blob/main/docs/schema-v1.md';

/** id -> title, why it matters, what to do. Severities vary per finding; `level` is the usual one. */
export const RULES = {
  'undeclared-env': { title: 'Reads a setting its listing does not declare', level: 'high', why: 'The registry listing is what catalogs, install tools and agents read before installing. A credential the code reads but the listing does not mention reaches the user only through the README, or at runtime. Many servers do document it in their README; when they do, mcpscan says so and reports it as worth knowing rather than as a hidden read. A name that appears only inside a string, such as example code a server hands to the agent, is reported as info: nothing reads it.', fix: 'Declare every environment variable in the server.json listing, marking credentials isSecret.' },
  'dynamic-env': { title: 'Builds an environment variable name at runtime', level: 'info', why: 'A computed name cannot be checked statically, so what it reads is unknown until it runs.', fix: 'Read variables by literal name where possible.' },
  'install-script': { title: 'Runs code when installed', level: 'high', why: 'Install-time code runs with the installing user\'s rights before anyone has used, or reviewed, the server: the classic supply-chain entry point.', fix: 'Remove install-time scripts; publish a wheel for Python packages.' },
  'network-egress': { title: 'Contacts an external host', level: 'info', why: 'Every host in the code is somewhere data can go. Hosts the listing names are expected; others are worth a look.', fix: 'Name the hosts the server talks to in its listing or README.' },
  capability: { title: 'Has a powerful capability', level: 'info', why: 'Running programs, evaluating code, or writing files decides how much damage a compromised or misled server can do.', fix: 'Say so in the tool descriptions; scope it as narrowly as possible.' },
  provenance: { title: 'Cannot be traced to its source', level: 'medium', why: 'Without a linked repository, an integrity match or a history, nothing ties the published code to code anyone reviewed.', fix: 'Link the source repository and publish from CI with provenance.' },
  'provenance-dropped': { title: 'Stopped publishing with provenance', level: 'medium', why: 'Earlier releases were built by CI from a named repository and this one was not: the pattern of a release published from somewhere else, such as a stolen token.', fix: 'Confirm who published this release before installing it.' },
  'publisher-mismatch': { title: 'Built from a different repository than it links to', level: 'medium', why: 'The attestation says where the code was built; the project says where to read it. When they differ, the code you read is not the code you run.', fix: 'Check the repository named in the attestation.' },
  'archived-upstream': { title: 'Archived by the MCP project', level: 'medium', why: 'The MCP project moved this reference server to its archive: nobody fixes it any more, including for security. Its registry does not say so. The NSA MCP guidance opens with "choose supported MCP projects".', fix: 'Use a maintained alternative; the archive README lists where each server went.' },
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
  'tool-name-collision': { title: 'Shares a tool name with another server you trust', level: 'medium', why: 'A client resolves a tool call by name. Two different servers offering the same name is how a malicious or compromised one hijacks calls meant for the trusted one \u2014 the NSA MCP guidance calls this tool invocation path confusion.', fix: 'Rename one, or remove whichever server you trust less; check which one actually answers the call.' },
  'unpinned-launch': { title: 'Launches whatever version is newest', level: 'medium', why: 'npx or uvx without a version runs the latest release at every start, so a bad release reaches you without any action on your part.', fix: 'Pin an exact version in the launch command.' },
  'not-scanned': { title: 'Configured server not scanned', level: 'info', why: 'Its launch method is not one mcpscan reads yet.', fix: 'None needed.' },
  'scan-error': { title: 'The scan failed', level: 'info', why: 'Something went wrong fetching or reading this server.', fix: 'Run it again; report it if it persists.' },
  'deprecated-transport': { title: 'Uses a deprecated transport', level: 'low', why: 'HTTP+SSE was deprecated in 2025-03-26 and is eligible for removal from the protocol; clients will drop it, and it predates the transport\'s current security guidance.', fix: 'Move the server to Streamable HTTP.' },
  'listing-status': { title: 'Deprecated or removed from the registry', level: 'high', why: 'Registry maintainers mark a listing deleted when it breaks the moderation policy (spam, malware, impersonation); a publisher marks it deprecated when it should not be used.', fix: 'Do not install a deleted listing. For a deprecated one, find its replacement.' },
  'local-network-exposed': { title: 'Reachable from your network', level: 'medium', why: 'It listens on every network interface, so other machines on your network (a café, an office, a hotel) can reach it. With no sign-in, anyone there can list and call its tools. The MCP specification says local servers should bind to localhost.', fix: 'Bind to 127.0.0.1, or require sign-in.' },
  'no-origin-validation': { title: 'Any website can drive it', level: 'high', why: 'It answers requests carrying another website\'s Origin. Through DNS rebinding, any page you open can then list and call its tools from your own browser: the class of the MCP Inspector remote-code-execution bug (CVE-2025-49596). The MCP specification requires servers to reject these requests.', fix: 'Reject requests whose Origin is not your own (HTTP 403), and bind to localhost.' },
  unauthenticated: { title: 'Answers without sign-in', level: 'info', why: 'Anyone who has the URL can list the tools and usually call them. Right for a public documentation server; wrong for anything that touches private data (the NSA MCP guidance lists unauthenticated servers first among what to look for).', fix: 'If it reaches anything private, put it behind OAuth as the MCP authorization specification describes.' },
  'custom-auth': { title: 'Uses its own sign-in', level: 'info', why: 'The server asks for its own key or token rather than MCP\'s OAuth flow, which the specification allows. It means a long-lived credential in a config file, usually with the full rights of the account that made it.', fix: 'Use a key scoped to what the server needs, and reference it from the environment rather than pasting it into a config.' },
  'oauth-metadata-missing': { title: 'Sign-in cannot be discovered', level: 'medium', why: 'The MCP specification requires a server that needs sign-in to publish OAuth protected resource metadata (RFC 9728) naming its authorization server. Without it, standard clients cannot sign in, and users get pushed toward pasting long-lived tokens instead.', fix: 'Serve /.well-known/oauth-protected-resource with authorization_servers, and point to it from WWW-Authenticate.' },
  'oauth-resource-mismatch': { title: 'Tokens bound to a different server', level: 'medium', why: 'The resource metadata names another resource than the server itself, so tokens are issued for a different audience; a token meant for one server may be accepted by another.', fix: 'Make the resource value the server\'s own canonical URI.' },
  'oauth-issuer-mismatch': { title: 'Authorization server metadata does not match its issuer', level: 'medium', why: 'Clients must reject metadata whose issuer differs from where it was discovered: it is the signature of an authorization-server mix-up attack, and conforming clients will refuse to sign in.', fix: 'Serve metadata whose issuer is exactly the issuer URL.' },
  'oauth-no-pkce': { title: 'Sign-in without PKCE', level: 'medium', why: 'PKCE stops an intercepted authorization code from being exchanged for a token. OAuth 2.1, which MCP authorization builds on, requires it, and the server does not advertise S256.', fix: 'Support PKCE S256 and list it in code_challenge_methods_supported.' },
  'oauth-dcr-only': { title: 'Registration only through a deprecated mechanism', level: 'low', why: 'MCP 2026-07-28 deprecated Dynamic Client Registration in favour of Client ID Metadata Documents; clients following the current revision prefer CIMD.', fix: 'Support client_id_metadata_document_supported.' },
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

/** How the catalog is grouped, for docs/checks.md and the web page. Every id must appear once. */
export const CHECK_GROUPS = [
  ['Package code and metadata (npm, PyPI)', ['undeclared-env', 'dynamic-env', 'install-script', 'network-egress', 'capability', 'instruction-like-text', 'typosquat', 'known-vulnerability', 'vuln-lookup-failed']],
  ['Where the code came from', ['provenance', 'provenance-dropped', 'publisher-mismatch', 'deprecated', 'archived-upstream']],
  ['The registry listing', ['listing-status', 'multiple-listings', 'no-package']],
  ['MCP servers on your own machine or network (--local)', ['local-network-exposed', 'no-origin-validation']],
  ['Hosted servers: sign-in', ['unauthenticated', 'custom-auth', 'oauth-metadata-missing', 'oauth-resource-mismatch', 'oauth-issuer-mismatch', 'oauth-no-pkce', 'oauth-dcr-only']],
  ['Hosted servers (probe and pins)', ['remote-not-probed', 'deprecated-transport', 'pinned', 'pins-updated', 'tool-description-changed', 'tool-schema-changed', 'tool-added', 'tool-removed', 'tools-truncated']],
  ['What your agents already trust (--installed)', ['plaintext-secret', 'credential-unresolved', 'unpinned-launch', 'tool-name-collision', 'not-scanned', 'scan-error']],
  ['Semantic judgment (optional)', ['undisclosed-capability', 'disclosure-unclear', 'disclosure-not-judged']],
];
