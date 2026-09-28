/**
 * `--local`: MCP servers listening on this machine (every listening TCP port, from the
 * operating system), or on a private network range you name (`--subnet`). Read-only:
 * discovery requests only, never a tool call. See local-core.js for what is judged, and why.
 */
import { readFileSync, readdirSync, readlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { connect } from 'node:net';
import { COMMON_PORTS, findMcpEndpoint, validatesOrigin, judgeLocal } from './local-core.js';
import { privateAddress } from './relay-core.js';
import { SEVERITY_ORDER } from './checks.js';

/** Ports that are databases or system services: an HTTP request tells us nothing, and some log it as an attack. */
const SKIP = new Set([22, 25, 53, 111, 135, 139, 445, 631, 3306, 5432, 6379, 9042, 11211, 27017]);

function hexToIp(hex) {
  if (hex.length === 8) return hex.match(/../g).reverse().map((b) => parseInt(b, 16)).join('.');
  const words = hex.match(/.{8}/g).map((w) => w.match(/../g).reverse().join(''));
  const groups = words.join('').match(/.{4}/g).map((g) => g.replace(/^0+(?=.)/, ''));
  const ip = groups.join(':');
  if (/^0:0:0:0:0:ffff:/.test(ip)) return ip.replace(/^0:0:0:0:0:ffff:/, '::ffff:');
  if (/^0(:0){7}$/.test(ip)) return '::';
  if (/^0(:0){6}:1$/.test(ip)) return '::1';
  return ip;
}

/** Linux: /proc/net/tcp{,6} in state LISTEN, with the owning process when it is ours to see. */
function listenersLinux() {
  const inodes = new Map();
  for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
    let text;
    try {
      text = readFileSync(f, 'utf8');
    } catch {
      continue;
    }
    for (const line of text.split('\n').slice(1)) {
      const c = line.trim().split(/\s+/);
      if (c.length < 10 || c[3] !== '0A') continue; // 0A = LISTEN
      const [addr, port] = c[1].split(':');
      inodes.set(c[9], { bind: hexToIp(addr), port: parseInt(port, 16), inode: c[9] });
    }
  }
  // inode -> process: readable for the user's own processes, which is what matters here.
  const owner = new Map();
  for (const pid of readdirSync('/proc').filter((d) => /^\d+$/.test(d))) {
    let fds;
    try {
      fds = readdirSync(`/proc/${pid}/fd`);
    } catch {
      continue;
    }
    for (const fd of fds) {
      let link;
      try {
        link = readlinkSync(`/proc/${pid}/fd/${fd}`);
      } catch {
        continue;
      }
      const m = /^socket:\[(\d+)\]$/.exec(link);
      if (m && inodes.has(m[1]) && !owner.has(m[1])) {
        let cmd = '';
        try {
          cmd = readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean).slice(0, 3).join(' ');
        } catch { /* gone */ }
        owner.set(m[1], `${cmd.slice(0, 80) || '?'} [pid ${pid}]`);
      }
    }
  }
  return [...inodes.values()].map((l) => ({ bind: l.bind, port: l.port, process: owner.get(l.inode) ?? null }));
}

/** macOS and others: lsof. Windows: netstat. Both best effort. */
function listenersOther() {
  try {
    const out = execFileSync('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return out.split('\n').slice(1).filter(Boolean).map((l) => {
      const c = l.trim().split(/\s+/);
      const m = /^(.*):(\d+)$/.exec(c[8] ?? '');
      return m ? { bind: m[1] === '*' ? '0.0.0.0' : m[1].replace(/^\[|\]$/g, ''), port: Number(m[2]), process: `${c[0]} [pid ${c[1]}]` } : null;
    }).filter(Boolean);
  } catch { /* no lsof */ }
  try {
    const out = execFileSync('netstat', ['-ano', '-p', 'TCP'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return out.split('\n').filter((l) => /LISTENING/.test(l)).map((l) => {
      const c = l.trim().split(/\s+/);
      const m = /^(.*):(\d+)$/.exec(c[1] ?? '');
      return m ? { bind: m[1].replace(/^\[|\]$/g, ''), port: Number(m[2]), process: `pid ${c[4]}` } : null;
    }).filter(Boolean);
  } catch {
    return [];
  }
}

export function listeningPorts() {
  const all = process.platform === 'linux' ? listenersLinux() : listenersOther();
  // One entry per port: prefer the widest binding, since that is the exposure.
  const byPort = new Map();
  for (const l of all) {
    const prev = byPort.get(l.port);
    const wide = (b) => ['0.0.0.0', '::'].includes(b);
    if (!prev || (wide(l.bind) && !wide(prev.bind))) byPort.set(l.port, { ...l, process: l.process ?? prev?.process ?? null });
  }
  return [...byPort.values()].filter((l) => !SKIP.has(l.port) && (l.port >= 1024 || l.port === 80)).sort((a, b) => a.port - b.port);
}

/** Where to reach a listener from this machine. */
function hostFor(bind) {
  if (bind === '0.0.0.0' || bind === '127.0.0.1' || bind.startsWith('127.')) return '127.0.0.1';
  if (bind === '::' || bind === '::1') return '[::1]';
  if (bind.startsWith('::ffff:')) return bind.slice(7);
  return bind.includes(':') ? `[${bind}]` : bind;
}

async function pool(items, limit, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  }));
  return out;
}

async function inspectListener({ host, port, bind, process: proc }) {
  const base = `http://${host}:${port}`;
  const found = await findMcpEndpoint(base);
  if (!found) return null;
  const originValidated = found.answered ? await validatesOrigin(found.url) : null;
  const server = { ...found, bind, process: proc, originValidated };
  const findings = judgeLocal(server).sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return {
    target: found.url,
    bind,
    process: proc,
    remote: { probed: found.answered, era: found.era ?? null, protocolVersion: found.protocolVersion ?? null, serverInfo: found.serverInfo ?? null, tools: found.tools?.length ?? 0, toolNames: (found.tools ?? []).map((t) => t.name), auth: found.auth ? { required: true } : { required: false }, originValidated },
    findings,
  };
}

/** Expand a private IPv4 CIDR of at most 256 addresses. */
export function expandSubnet(cidr) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(String(cidr).trim());
  if (!m) throw new Error('give the subnet as a.b.c.d/nn, for example 192.168.1.0/24');
  const bits = Number(m[5]);
  if (bits < 24 || bits > 32) throw new Error('scan at most a /24 (256 addresses) at a time');
  const base = (((Number(m[1]) << 24) >>> 0) + (Number(m[2]) << 16) + (Number(m[3]) << 8) + Number(m[4])) >>> 0;
  const size = 2 ** (32 - bits);
  const start = (base & ~(size - 1)) >>> 0;
  const ips = Array.from({ length: size }, (_, i) => {
    const n = (start + i) >>> 0;
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  });
  if (!privateAddress(ips[0]) || !privateAddress(ips.at(-1))) throw new Error('--subnet only scans private ranges (10/8, 172.16/12, 192.168/16): your own network');
  return size > 2 ? ips.slice(1, -1) : ips; // skip network and broadcast addresses
}

function tcpOpen(host, port, timeoutMs = 400) {
  return new Promise((resolve) => {
    const s = connect({ host, port });
    const done = (v) => {
      s.destroy();
      resolve(v);
    };
    s.setTimeout(timeoutMs, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

/**
 * @param {{subnet?: string, ports?: number[]}} [opts]
 * @returns {Promise<{scope: string, checked: number, servers: object[]}>}
 */
export async function scanLocal({ subnet, ports = COMMON_PORTS } = {}) {
  if (!subnet) {
    const listeners = listeningPorts();
    const results = await pool(listeners.map((l) => ({ ...l, host: hostFor(l.bind) })), 8, inspectListener);
    return { scope: 'this machine', checked: listeners.length, servers: results.filter(Boolean) };
  }
  const hosts = expandSubnet(subnet);
  const pairs = hosts.flatMap((host) => ports.map((port) => ({ host, port })));
  const open = (await pool(pairs, 128, async (p) => ((await tcpOpen(p.host, p.port)) ? p : null))).filter(Boolean);
  // Another machine's server was reached over the network, so it is by definition exposed to it.
  const results = await pool(open.map((p) => ({ ...p, bind: 'network', process: null })), 8, async (p) => {
    const r = await inspectListener({ ...p, bind: null });
    if (r && r.remote.probed) {
      r.findings.unshift({
        check: 'local-network-exposed',
        severity: 'high',
        message: `answers MCP from across your network with no sign-in: anyone on the network can list and call its ${r.remote.tools} tool(s)`,
        evidence: [{ file: `${p.host}:${p.port}`, line: 0, text: 'reached from this machine over the network' }],
      });
    }
    return r;
  });
  return { scope: subnet, checked: pairs.length, open: open.length, servers: results.filter(Boolean) };
}
