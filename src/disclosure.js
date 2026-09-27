/**
 * The semantic check: does what the user is TOLD cover what the code CAN DO?
 *
 * Static checks find the capabilities (exec, file writes, eval, sockets, external
 * hosts). This asks one Noul per capability actually present — never speculative ones,
 * since an unasked question costs nothing and an asked one costs tokens — over the
 * descriptions a user reads before installing.
 *
 * The state holds ONLY the user-visible surface: server and tool descriptions. Put the
 * code or the host list in the state and the model would judge what the server does,
 * which static analysis already knows. The question is what the user was told.
 */
import { extractTools } from './tools.js';

/**
 * Starting thresholds, taken from TypeSafe's documented three-way split
 * (https://docs.typesafe.ai/primitives/noul). NOT yet calibrated on labelled MCP
 * servers — that is the next piece of work, and until then a middle-band answer goes
 * to a human rather than to either code path.
 */
export const DEFAULT_THRESHOLDS = { yes: 0.8, no: 0.2 };

/** Capability label (from checkCapabilities / egress) -> one Noul question. */
const QUESTIONS = {
  'process execution': {
    id: 'discloses_process_execution',
    capability: 'run commands or other programs',
    instructions:
      'Do the descriptions in `server` or `tools` tell a user that this server can run shell commands or start other programs on their machine?',
    criteria: {
      true: 'At least one description says or clearly implies that it runs commands, scripts, or other programs',
      false: 'No description mentions running commands, scripts, or programs',
    },
  },
  'dynamic code evaluation': {
    id: 'discloses_code_execution',
    capability: 'execute code supplied or generated at runtime',
    instructions:
      'Do the descriptions in `server` or `tools` tell a user that this server can execute code it is given or generates while running?',
    criteria: {
      true: 'At least one description says it evaluates, runs, or executes code',
      false: 'No description mentions executing code',
    },
  },
  'filesystem writes or deletes': {
    id: 'discloses_file_writes',
    capability: 'create, change, or delete files',
    instructions:
      'Do the descriptions in `server` or `tools` tell a user that this server can create, modify, or delete files on their machine?',
    criteria: {
      true: 'At least one description says it writes, saves, edits, moves, or deletes files',
      false: 'Descriptions only mention reading, or do not mention files at all',
    },
  },
  'raw network sockets': {
    id: 'discloses_raw_network',
    capability: 'open raw network connections',
    instructions:
      'Do the descriptions in `server` or `tools` tell a user that this server opens direct network connections to other machines?',
    criteria: {
      true: 'At least one description mentions connecting to hosts, ports, or network services',
      false: 'No description mentions network connections',
    },
  },
  'external services': {
    id: 'discloses_external_services',
    capability: 'send requests to external services',
    instructions:
      'Do the descriptions in `server` or `tools` tell a user that this server sends requests to an external web service or API?',
    criteria: {
      true: 'At least one description names or clearly implies an outside service, API, or website it calls',
      false: 'Descriptions read as if everything happens locally',
    },
  },
};

// The python exec pattern is the same disclosure question as the JS one.
const ALIASES = { 'process execution (python)': 'process execution' };

/** Collect present capabilities and their code evidence from the static findings. */
function presentCapabilities(findings) {
  const present = new Map(); // question key -> evidence[]
  for (const f of findings) {
    let key = null;
    if (f.check === 'capability') {
      const label = f.message.replace(/^uses /, '');
      key = ALIASES[label] ?? label;
    } else if (f.check === 'network-egress') {
      key = 'external services';
    }
    if (!key || !QUESTIONS[key]) continue;
    if (!present.has(key)) present.set(key, []);
    const ev = present.get(key);
    for (const e of f.evidence ?? []) if (ev.length < 3) ev.push(e);
  }
  return present;
}

/**
 * @returns {Promise<{findings: object[], disclosure: object}>}
 *   disclosure carries the raw probabilities so they can be labelled and used to
 *   calibrate thresholds later, instead of being thrown away after thresholding.
 */
export async function checkDisclosure({ pkg, entry, findings, judge, thresholds = DEFAULT_THRESHOLDS }) {
  const present = presentCapabilities(findings);
  const { tools, truncated } = extractTools(pkg.files);
  const disclosure = { judged: false, model: null, tools: tools.length, truncated, judgments: {} };

  if (present.size === 0) {
    return { findings: [], disclosure: { ...disclosure, reason: 'no capabilities to disclose' } };
  }
  if (tools.length === 0) {
    return {
      findings: [
        {
          check: 'disclosure-not-judged',
          severity: 'info',
          message: 'no tool descriptions could be found statically, so disclosure was not judged',
          evidence: [{ file: pkg.name, line: 0, text: `capabilities present: ${[...present.keys()].join(', ')}` }],
        },
      ],
      disclosure: { ...disclosure, reason: 'no tool descriptions found' },
    };
  }

  const state = {
    server: {
      name: entry?.server?.name ?? pkg.name,
      description: entry?.server?.description ?? pkg.manifest?.description ?? '',
    },
    tools: tools.map((t) => ({ name: t.name, description: t.description })),
  };

  const questions = {};
  for (const key of present.keys()) {
    const q = QUESTIONS[key];
    questions[q.id] = { type: 'noul', instructions: q.instructions, criteria: q.criteria };
  }

  const partialTools = tools.filter((t) => t.partial).length;
  disclosure.partialTools = partialTools;

  const res = await judge.ask(state, questions);
  disclosure.judged = true;
  disclosure.model = res.model ?? null;
  disclosure.usage = res.usage ?? null;

  const out = [];
  for (const [key, evidence] of present) {
    const q = QUESTIONS[key];
    const p = res.answers[q.id].noul;
    disclosure.judgments[key] = p;

    if (p <= thresholds.no && partialTools > 0) {
      // Missing text could hold the disclosure: unknown is neither clean nor guilty.
      out.push({
        check: 'disclosure-unclear',
        subject: key,
        severity: 'info',
        message: `can ${q.capability}; no description says so (p=${p.toFixed(2)}), but ${partialTools} description(s) could only be read in part, so this is not called undisclosed`,
        evidence,
      });
    } else if (p <= thresholds.no) {
      out.push({
        check: 'undisclosed-capability',
        subject: key,
        severity: 'medium',
        message: `can ${q.capability}, but no description tells the user (p=${p.toFixed(2)})`,
        evidence,
      });
    } else if (p < thresholds.yes) {
      out.push({
        check: 'disclosure-unclear',
        subject: key,
        severity: 'info',
        message: `can ${q.capability}; the model is split on whether the descriptions say so (p=${p.toFixed(2)}), review by hand`,
        evidence,
      });
    }
  }
  return { findings: out, disclosure };
}
