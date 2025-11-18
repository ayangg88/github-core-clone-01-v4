// Entry point: boot the forge, join the trial env, and stay up until the env
// says the trial is done.
//
// The env hands us its base URL in MAKEFUN_ENV_URL. The contract is:
//   1. listen on an ephemeral port (never a fixed one),
//   2. POST {"port": <port>} to $MAKEFUN_ENV_URL/register,
//   3. keep polling GET $MAKEFUN_ENV_URL/done until it answers {"done": true},
//   4. shut the server down and exit 0.
// Nothing here does forge work; the whole server lives in app.ts.

import http from 'node:http';
import { createApp } from './app.ts';

const envBase = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envBase === '') {
  process.stderr.write('[forge] MAKEFUN_ENV_URL is not set, so there is no env to join\n');
  process.exit(1);
}

const FETCH_TIMEOUT_MS = 10_000;
const POLL_START_MS = 250;
const POLL_MAX_MS = 2_000;

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postJson(url: string, value: unknown): Promise<{ status: number; text: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(value),
      signal: ctrl.signal,
    });
    return { status: res.status, text: await res.text() };
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(url: string): Promise<{ status: number; text: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    return { status: res.status, text: await res.text() };
  } finally {
    clearTimeout(timer);
  }
}

async function main(): Promise<void> {
  const app = createApp();
  await new Promise<void>((resolve, reject) => {
    app.once('error', reject);
    app.listen(0, '127.0.0.1', () => resolve());
  });
  const address = app.address();
  if (typeof address !== 'object' || address === null) {
    process.stderr.write('[forge] could not read the listen address\n');
    process.exit(1);
  }
  const port = address.port;

  // Register with the env, retrying with backoff until it accepts us.
  let failures = 0;
  for (;;) {
    try {
      const { status, text } = await postJson(`${envBase}/register`, { port });
      if (status === 200 || status === 201) break;
      process.stderr.write(`[forge] register answered ${status}: ${text.slice(0, 200)}\n`);
    } catch (err) {
      process.stderr.write(`[forge] register failed: ${err instanceof Error ? err.message : String(err)}\n`);
    }
    failures += 1;
    await wait(Math.min(POLL_MAX_MS, POLL_START_MS * 2 ** Math.min(failures, 4)));
  }

  // Poll /done until the trial ends.
  failures = 0;
  for (;;) {
    try {
      const { status, text } = await getJson(`${envBase}/done`);
      if (status === 200) {
        const parsed = JSON.parse(text) as { done?: unknown };
        if (parsed.done === true) break;
      }
      failures = 0;
    } catch {
      failures += 1;
    }
    await wait(Math.min(POLL_MAX_MS, POLL_START_MS * 2 ** Math.min(failures, 4)));
  }

  await new Promise<void>((resolve) => app.close(() => resolve()));
  process.exit(0);
}

main().catch((err) => {
  process.stderr.write(`[forge] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
