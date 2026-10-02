/**
 * The seam between deedroll and whatever answers semantic questions.
 *
 * A judge has one method: ask(state, questions) -> { model, answers, usage }, in the
 * TypeSafe System One wire shape. The TypeSafe implementation below is one provider;
 * a fine-tuned encoder or a reasoning model can sit behind the same interface without
 * the checks changing. That is what keeps the provider a two-way door.
 */

const ENDPOINT = 'https://api.typesafe.ai/v1/systemone';

export class JudgeConfigError extends Error {}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @param {object} [opts]
 * @param {string} [opts.apiKey]      defaults to TYPESAFE_API_KEY, the name TypeSafe's own SDKs read
 * @param {string} [opts.model]       "jev-latest" per https://docs.typesafe.ai/api
 * @param {Function} [opts.fetchImpl] injectable for tests
 * @param {Function} [opts.sleep]     injectable for tests
 */
export function createTypeSafeJudge({
  apiKey = process.env.TYPESAFE_API_KEY,
  model = 'jev-latest',
  endpoint = ENDPOINT,
  fetchImpl = globalThis.fetch,
  maxRetries = 4,
  baseDelayMs = 500,
  sleep = defaultSleep,
} = {}) {
  if (!apiKey) {
    throw new JudgeConfigError(
      'the semantic check needs a TypeSafe API key: set TYPESAFE_API_KEY (https://typesafe.ai)'
    );
  }

  return {
    name: 'typesafe',
    model,

    async ask(state, questions) {
      const body = JSON.stringify({ state, model, questions });

      for (let attempt = 0; ; attempt++) {
        const res = await fetchImpl(endpoint, {
          method: 'POST',
          headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
          body,
        });

        if (res.ok) {
          const out = await res.json();
          assertComplete(out, questions);
          return out;
        }

        // 429 rate limit and 529 overloaded are the two the docs say to retry.
        if ((res.status === 429 || res.status === 529) && attempt < maxRetries) {
          const delay = baseDelayMs * 2 ** attempt + Math.floor(Math.random() * baseDelayMs);
          await sleep(delay);
          continue;
        }

        const detail = await res.text().catch(() => '');
        if (res.status === 401) {
          throw new JudgeConfigError('TypeSafe rejected the API key (401): check TYPESAFE_API_KEY');
        }
        throw new Error(`TypeSafe ${res.status}${detail ? `: ${detail.slice(0, 300)}` : ''}`);
      }
    },
  };
}

/**
 * Every question must come back with a well-formed answer.
 *
 * The failure this prevents: a missing answer read as 0 would mark every capability
 * "undisclosed", and the scanner would manufacture findings out of an API hiccup.
 */
function assertComplete(out, questions) {
  const answers = out?.answers ?? {};
  for (const [id, q] of Object.entries(questions)) {
    const a = answers[id];
    if (!a || a.type !== q.type) {
      throw new Error(`TypeSafe response is missing a ${q.type} answer for "${id}"`);
    }
    if (q.type === 'noul' && (typeof a.noul !== 'number' || a.noul < 0 || a.noul > 1)) {
      throw new Error(`TypeSafe returned an out-of-range noul for "${id}": ${a.noul}`);
    }
  }
}
