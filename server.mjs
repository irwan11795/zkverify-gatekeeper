// Proof Gatekeeper agent endpoint — zkVerify Agent Games
// Node.js stdlib only (+ snarkjs from work-dir node_modules).
// Contract: https://agentgames.zkverify.io/build
// - POST /agent : signed task envelopes (preflight + proof-gatekeeper v1)
// - HMAC-SHA256 over the RAW body, header x-agent-games-signature, verified BEFORE parsing.
// - Deterministic decision in code (five conditions). Groth16 proof via snarkjs (~1.5 s).
// - Optional Kurier submission (KURIER_API_KEY) with a bounded poll; never blocks past the budget.
// - Fail closed everywhere. No secrets in logs.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

const PORT = Number(process.env.PORT || 8787);
const WASM = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const STATE_FILE = path.join(__dirname, 'agent-state.json');
const LOG_FILE = path.join(__dirname, 'agent-log.jsonl');
const KURIER_API_URL = 'https://api.kurier.xyz/api/v1';

// Published by the platform: /api/circuit-info (gatekeeper vkHash, mainnet)
const REGISTERED_VK_HEX = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const REGISTERED_VK_DEC = BigInt(REGISTERED_VK_HEX).toString();

// Timing budgets (ms). Hard platform deadline is 60 s.
const PROOF_BUDGET_MS = 20_000;   // snarkjs prove normally ~1.5 s
// Measured 2026-11-15: Kurier submit ~0.9 s, optimisticVerify success,
// IncludedInBlock + txHash at ~4 s, but Finalized NOT reached within 180 s
// (job still "Submitted" 4+ min after submit; aggregation is slow). The 60 s
// platform deadline makes waiting for Finalized infeasible, and the response
// carries the local proof regardless, so poll only long enough to confirm
// submission + inclusion, then answer with the local proof.
const KURIER_BUDGET_MS = 12_000;  // bounded poll; respond with local proof if exceeded
const TOTAL_BUDGET_MS = 50_000;

function hmacSecret() {
  const s = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim();
  return s && s !== 'PLACEHOLDER' ? s : null;
}
function kurierKey() {
  const k = (process.env.KURIER_API_KEY || '').trim();
  return k && k !== 'PLACEHOLDER' ? k : null;
}

function log(obj) {
  const line = JSON.stringify({ t: new Date().toISOString(), ...obj });
  fs.appendFileSync(LOG_FILE, line + '\n');
  console.log(line);
}

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch { return { seenTaskIds: {}, seenProofTx: {} }; }
}
function saveState(s) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
}
let state = loadState();

function signBody(rawBuf) {
  const secret = hmacSecret();
  if (!secret) return null;
  return crypto.createHmac('sha256', secret).update(rawBuf).digest('hex');
}

function verifySignature(rawBuf, header) {
  const secret = hmacSecret();
  if (!secret) return { ok: false, reason: 'NO_SECRET_CONFIGURED' };
  if (!header) return { ok: false, reason: 'MISSING_SIGNATURE' };
  const given = header.startsWith('sha256=') ? header.slice(7) : header;
  const expected = crypto.createHmac('sha256', secret).update(rawBuf).digest('hex');
  let ok = false;
  try {
    ok = given.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(given, 'utf8'), Buffer.from(expected, 'utf8'));
  } catch { ok = false; }
  return { ok, reason: ok ? null : 'BAD_SIGNATURE' };
}

function sendJson(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj));
  const sig = signBody(raw);
  const headers = { 'content-type': 'application/json' };
  if (sig) headers['x-agent-games-signature'] = sig;
  res.writeHead(status, headers);
  res.end(raw);
}

// taskId (string like "gk_8d31_...") -> field element: keccak256 of the UTF-8 string.
// snarkjs reduces mod p on input; the public signal is the reduced value.
function taskIdToField(taskId) {
  const h = crypto.createHash('sha3-256').update(taskId, 'utf8').digest('hex');
  return BigInt('0x' + h).toString();
}
function hexToDec(v) {
  if (typeof v === 'number') return BigInt(v).toString();
  const s = String(v).trim();
  return (s.startsWith('0x') || s.startsWith('0X') ? BigInt(s) : BigInt(s)).toString();
}

async function prove(input, timeoutMs) {
  return await Promise.race([
    snarkjs.groth16.fullProve(input, WASM, ZKEY),
    new Promise((_, rej) => setTimeout(() => rej(new Error('PROVE_TIMEOUT')), timeoutMs)),
  ]);
}

async function kurierSubmit(proof, publicSignals) {
  const key = kurierKey();
  if (!key) return { status: 'skipped', reason: 'NO_KURIER_KEY' };
  const t0 = Date.now();
  try {
    const res = await fetch(`${KURIER_API_URL}/submit-proof/${key}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(15_000),
      body: JSON.stringify({
        proofType: 'groth16',
        vkRegistered: true,
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof, publicSignals, vk: REGISTERED_VK_HEX },
      }),
    });
    const job = await res.json().catch(() => ({}));
    const jobId = job.jobId || job.id || job.job_id || null;
    if (!res.ok || !jobId) {
      return { status: 'submit_failed', httpStatus: res.status, detail: JSON.stringify(job).slice(0, 300) };
    }
    // Poll for Finalized. Verified endpoint (2026-11-15, live test):
    // GET /api/v1/job-status/{apiKey}/{jobId} — statuses Submitted -> IncludedInBlock -> Finalized.
    const pollPaths = [
      `${KURIER_API_URL}/job-status/${key}/${jobId}`,
    ];
    let lastStatus = null;
    while (Date.now() - t0 < KURIER_BUDGET_MS) {
      for (const url of pollPaths) {
        try {
          const r = await fetch(url, { headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(10_000) });
          if (!r.ok) continue;
          const j = await r.json().catch(() => ({}));
          const st = j.status || j.state || j.jobStatus || null;
          if (st) {
            lastStatus = st;
            if (/final/i.test(st)) {
              return { status: 'finalized', jobId, finalStatus: st, txHash: j.txHash || j.transactionHash || j.proof_tx || null, ms: Date.now() - t0 };
            }
            break; // found a working poll endpoint; stick to it
          }
        } catch { /* try next path */ }
      }
      await new Promise(r => setTimeout(r, 3000));
    }
    return { status: 'pending', jobId, lastStatus, ms: Date.now() - t0 };
  } catch (e) {
    return { status: 'error', detail: String(e && e.message || e).slice(0, 200) };
  }
}

function decide(input) {
  // Returns { decision: 'APPROVE'|'REJECT', reason_code, checks }
  const checks = {};
  checks.vkMatch = hexToDec(input.proof_vk) === hexToDec(input.registered_vk);
  if (!checks.vkMatch) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', checks };
  checks.balanceOk = BigInt(String(input.public_balance)) >= BigInt(String(input.minimum));
  if (!checks.balanceOk) return { decision: 'REJECT', reason_code: 'INSUFFICIENT_BALANCE', checks };
  checks.amountOk = BigInt(String(input.amount)) <= BigInt(String(input.max_transfer));
  if (!checks.amountOk) return { decision: 'REJECT', reason_code: 'AMOUNT_EXCEEDS_MAX', checks };
  checks.recipientOk = String(input.recipient).toLowerCase() === String(input.condition_recipient).toLowerCase();
  if (!checks.recipientOk) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', checks };
  checks.notExpired = BigInt(input.current_block) < BigInt(input.expiry_block);
  if (!checks.notExpired) return { decision: 'REJECT', reason_code: 'EXPIRED', checks };
  return { decision: 'APPROVE', reason_code: 'OK', checks };
}

async function handleGatekeeper(env, t0) {
  const input = env.input || {};
  const taskId = env.task_id || env.taskId || '';
  const proofTx = input.proof_tx || null;

  if (!taskId) return { status: 400, body: { decision: 'REJECT', reason_code: 'MALFORMED_ENVELOPE' } };
  if (state.seenTaskIds[taskId]) {
    return { status: 200, body: { decision: 'REJECT', reason_code: 'DUPLICATE_TASK', proof_tx: proofTx } };
  }
  if (proofTx && state.seenProofTx[proofTx]) {
    return { status: 200, body: { decision: 'REJECT', reason_code: 'PROOF_TX_REUSED', proof_tx: proofTx } };
  }

  const verdict = decide(input);
  const decisionBit = verdict.decision === 'APPROVE' ? '1' : '0';
  const salt = BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString();
  const circuitInput = {
    registeredVkHash: hexToDec(input.registered_vk),
    proofVkHash: hexToDec(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: hexToDec(input.recipient),
    conditionRecipient: hexToDec(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decisionBit,
    taskId: taskIdToField(taskId),
    salt,
  };

  let proof = null, publicSignals = null, proveError = null;
  const proveStart = Date.now();
  try {
    const r = await prove(circuitInput, PROOF_BUDGET_MS);
    proof = r.proof; publicSignals = r.publicSignals;
  } catch (e) {
    proveError = String(e && e.message || e).slice(0, 200);
  }
  const proveMs = Date.now() - proveStart;

  // A wrong APPROVE is unprovable by construction (circuit assert). If proving
  // an APPROVE failed, the decision must have been wrong: fail closed to REJECT
  // with a fresh decision=0 proof.
  if (!proof && verdict.decision === 'APPROVE') {
    log({ kind: 'approve_proof_failed_fallback_reject', taskId, proveError, proveMs });
    circuitInput.decision = '0';
    try {
      const r = await prove(circuitInput, PROOF_BUDGET_MS);
      proof = r.proof; publicSignals = r.publicSignals;
      verdict.decision = 'REJECT'; verdict.reason_code = 'PROOF_FAILED_FAIL_CLOSED';
    } catch (e2) {
      proveError = String(e2 && e2.message || e2).slice(0, 200);
    }
  }

  // Kurier: submit + bounded poll. Never let it eat the response budget.
  let kurier = { status: 'skipped', reason: 'NO_KURIER_KEY' };
  if (proof && Date.now() - t0 < TOTAL_BUDGET_MS - 5000) {
    kurier = await kurierSubmit(proof, publicSignals);
  }

  state.seenTaskIds[taskId] = { decision: verdict.decision, reason: verdict.reason_code, at: new Date().toISOString() };
  if (proofTx) state.seenProofTx[proofTx] = { taskId, at: new Date().toISOString() };
  saveState(state);

  const body = { decision: verdict.decision, reason_code: verdict.reason_code, proof_tx: proofTx };
  if (proof) { body.proof = proof; body.public_signals = publicSignals; }
  log({ kind: 'task', taskId, decision: verdict.decision, reason: verdict.reason_code, proveMs, proofOk: !!proof, kurier: kurier.status, ms: Date.now() - t0 });
  return { status: 200, body };
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const t0 = Date.now();
    const raw = Buffer.concat(chunks);
    const url = req.url || '/';
    try {
      if (req.method === 'GET' && (url === '/health' || url === '/')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, service: 'gatekeeper', time: new Date().toISOString() }));
        return;
      }
      if (req.method !== 'POST' || (url !== '/agent' && url !== '/agent/')) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'not_found' }));
        return;
      }
      // HMAC BEFORE parsing.
      const sig = verifySignature(raw, req.headers['x-agent-games-signature']);
      if (!sig.ok) {
        log({ kind: 'bad_signature', reason: sig.reason, path: url });
        return sendJson(res, 401, { error: 'bad_signature', reason: sig.reason });
      }
      let env;
      try { env = JSON.parse(raw.toString('utf8')); }
      catch { return sendJson(res, 400, { error: 'bad_json' }); }

      if (env.type === 'agent-games.preflight.v1') {
        log({ kind: 'preflight', agent_id: env.agent_id || null, ms: Date.now() - t0 });
        return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
      }
      if (env.type === 'agent-games.proof-gatekeeper.v1') {
        const out = await handleGatekeeper(env, t0);
        return sendJson(res, out.status, out.body);
      }
      log({ kind: 'unknown_type', type: env.type || null });
      return sendJson(res, 400, { error: 'unknown_type' });
    } catch (e) {
      log({ kind: 'server_error', detail: String(e && e.message || e).slice(0, 300), ms: Date.now() - t0 });
      try { return sendJson(res, 200, { decision: 'REJECT', reason_code: 'SERVER_ERROR' }); }
      catch { try { res.writeHead(500); res.end(); } catch {} }
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`gatekeeper listening on 127.0.0.1:${PORT} hmac=${hmacSecret() ? 'configured' : 'NOT CONFIGURED'} kurier=${kurierKey() ? 'configured' : 'NOT CONFIGURED'}`);
});
