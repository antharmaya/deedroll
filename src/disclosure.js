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
 * Step 1 of every judgment: decide whether there is anything to ask, and build the
 * exact request. Deterministic for a given package version, so a request can be
 * handed to an agent and its answers applied later (see agent-judge.js).
 *
 * @returns {{skip: {findings, disclosure}} | {request: {state, questions, present, tools, partialTools, truncated}}}
 */
export function buildDisclosureRequest({ pkg, entry, findings }) {
  const present = presentCapabilities(findings);
  const { tools, truncated } = extractTools(pkg.files);
  const base = { judged: false, model: null, tools: tools.length, truncated, judgments: {} };

  if (present.size === 0) {
    return { skip: { findings: [], disclosure: { ...base, reason: 'no capabilities to disclose' } } };
  }
  if (tools.length === 0) {
    return {
      skip: {
        findings: [
          {
            check: 'disclosure-not-judged',
            severity: 'info',
            message: 'no tool descriptions could be found statically, so disclosure was not judged',
            evidence: [{ file: pkg.name, line: 0, text: `capabilities present: ${[...present.keys()].join(', ')}` }],
          },
        ],
        disclosure: { ...base, reason: 'no tool descriptions found' },
      },
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
  return {
    request: { state, questions, present, tools, truncated, partialTools: tools.filter((t) => t.partial).length },
  };
}

/**
 * Step 2: turn a judge's answers into findings. Shared by every judge, so the
 * three-way split and the partial-description rule cannot drift between them.
 */
export function applyJudgments({ request, response, thresholds = DEFAULT_THRESHOLDS }) {
  const { present, tools, truncated, partialTools } = request;
  const disclosure = {
    judged: true,
    model: response.model ?? null,
    usage: response.usage ?? null,
    tools: tools.length,
    truncated,
    partialTools,
    judgments: {},
  };

  const out = [];
  for (const [key, evidence] of present) {
    const q = QUESTIONS[key];
    const a = response.answers[q.id];
    const p = a.noul;
    const note = a.note ? ` — ${a.note}` : '';
    // A categorical judge said yes/no/unsure; printing it as p=0.00 would fake a measurement.
    const how = a.label ? `judge: ${a.label}` : `p=${p.toFixed(2)}`;
    disclosure.judgments[key] = a.quote ? { p, quote: a.quote } : p;

    if (p <= thresholds.no && partialTools > 0) {
      // Missing text could hold the disclosure: unknown is neither clean nor guilty.
      out.push({
        check: 'disclosure-unclear',
        subject: key,
        severity: 'info',
        message: `can ${q.capability}; no description says so (${how}), but ${partialTools} description(s) could only be read in part, so this is not called undisclosed${note}`,
        evidence,
      });
    } else if (p <= thresholds.no) {
      out.push({
        check: 'undisclosed-capability',
        subject: key,
        severity: 'medium',
        message: `can ${q.capability}, but no description tells the user (${how})${note}`,
        evidence,
      });
    } else if (p < thresholds.yes) {
      out.push({
        check: 'disclosure-unclear',
        subject: key,
        severity: 'info',
        message: `can ${q.capability}; the judge is split on whether the descriptions say so (${how}), review by hand${note}`,
        evidence,
      });
    }
  }
  return { findings: out, disclosure };
}

/**
 * @returns {Promise<{findings: object[], disclosure: object}>}
 *   disclosure carries the raw judgments so they can be labelled and used to
 *   calibrate thresholds later, instead of being thrown away after thresholding.
 */
export async function checkDisclosure({ pkg, entry, findings, judge, thresholds = DEFAULT_THRESHOLDS }) {
  const built = buildDisclosureRequest({ pkg, entry, findings });
  if (built.skip) return built.skip;
  const response = await judge.ask(built.request.state, built.request.questions);
  return applyJudgments({ request: built.request, response, thresholds });
}
