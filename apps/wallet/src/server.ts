/**
 * Wallet HTTP layer + a minimal browser UI that drives the full demo:
 *   1) get a PID credential from the issuer (OpenID4VCI)
 *   2) present name + age proof to the verifier (OpenID4VP)
 */
import express from "express";
import { Wallet } from "./wallet.js";
import type { CredentialOffer } from "@digilompakko/core";

const PORT = Number(process.env.WALLET_PORT ?? 4000);
const ISSUER_URL = process.env.ISSUER_URL ?? "http://localhost:4001";
const VERIFIER_URL = process.env.VERIFIER_URL ?? "http://localhost:4002";

const wallet = new Wallet();
await wallet.init();

const app = express();
app.use(express.json());

// Step 1: obtain a credential via a fresh offer from the issuer.
app.post("/api/get-credential", async (_req, res) => {
  try {
    const offer = (await (await fetch(`${ISSUER_URL}/offer`, { method: "POST" })).json()) as CredentialOffer;
    const stored = await wallet.acceptOffer(offer);
    res.json({ ok: true, vct: stored.vct, count: wallet.credentials.length });
  } catch (e) {
    res.status(400).json({ ok: false, error: (e as Error).message });
  }
});

// Step 1b: obtain a credential via the Authorization Code + PAR + PKCE flow.
app.post("/api/get-credential-authcode", async (_req, res) => {
  try {
    const stored = await wallet.acceptViaAuthCode(ISSUER_URL);
    res.json({ ok: true, vct: stored.vct, count: wallet.credentials.length, flow: "authorization_code+PAR+PKCE" });
  } catch (e) {
    res.status(400).json({ ok: false, error: (e as Error).message });
  }
});

// Step 2: respond to a verifier presentation request.
app.post("/api/present", async (req, res) => {
  try {
    const reveal: string[] | undefined = req.body?.reveal;
    const { request_uri } = (await (await fetch(`${VERIFIER_URL}/presentation/request`, { method: "POST" })).json()) as { request_uri: string };
    const { result } = await wallet.present(request_uri, reveal);
    res.json({ ok: true, result });
  } catch (e) {
    res.status(400).json({ ok: false, error: (e as Error).message });
  }
});

app.get("/", (_req, res) => res.type("html").send(UI));

app.listen(PORT, () => {
  console.log(`[wallet]   Holder wallet UI on http://localhost:${PORT}`);
  console.log(`[wallet]   issuer=${ISSUER_URL}  verifier=${VERIFIER_URL}`);
});

const UI = /* html */ `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Digilompakko — demo wallet</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem;color:#15202b}
  h1{font-size:1.4rem} .card{border:1px solid #d7dee6;border-radius:12px;padding:1rem 1.25rem;margin:1rem 0}
  button{background:#1565c0;color:#fff;border:0;border-radius:8px;padding:.6rem 1rem;font-size:1rem;cursor:pointer}
  button:disabled{opacity:.5;cursor:default} pre{background:#0f1b2a;color:#d6f5d6;padding:1rem;border-radius:8px;overflow:auto}
  label{display:inline-flex;gap:.4rem;align-items:center;margin-right:1rem} .muted{color:#5b6b7b;font-size:.9rem}
  .ok{color:#1b7f3b;font-weight:600}.bad{color:#c0392b;font-weight:600}
</style></head><body>
<h1>🇫🇮 Digilompakko — EUDI demo wallet</h1>
<p class="muted">SD-JWT VC over OpenID4VCI / OpenID4VP, ES256 holder binding. Demo only.</p>

<div class="card">
  <h2>1 · Get your PID credential</h2>
  <p class="muted">Wallet redeems a credential offer from the issuer and stores an SD-JWT VC bound to your holder key.</p>
  <button id="get">Receive credential (pre-auth)</button>
  <button id="getAuth">Receive via Auth Code + PAR + PKCE</button>
  <p id="getOut"></p>
</div>

<div class="card">
  <h2>2 · Present to a relying party</h2>
  <p class="muted">Choose what to disclose. The verifier asks for name + proof of age — you reveal only what you pick.</p>
  <div>
    <label><input type="checkbox" class="rev" value="given_name" checked> given_name</label>
    <label><input type="checkbox" class="rev" value="family_name" checked> family_name</label>
    <label><input type="checkbox" class="rev" value="age_over_18" checked> age_over_18</label>
  </div>
  <p><button id="present" disabled>Present</button></p>
  <pre id="presentOut" hidden></pre>
</div>

<script>
const $ = (s) => document.querySelector(s);
async function getCredential(endpoint) {
  $("#get").disabled = true; $("#getAuth").disabled = true; $("#getOut").textContent = "Requesting…";
  const r = await (await fetch(endpoint, {method:"POST"})).json();
  if (r.ok) { $("#getOut").innerHTML = '<span class="ok">✓ stored ' + r.vct + (r.flow ? ' via ' + r.flow : '') + '</span>'; $("#present").disabled = false; }
  else { $("#getOut").innerHTML = '<span class="bad">✗ ' + r.error + '</span>'; $("#get").disabled = false; $("#getAuth").disabled = false; }
}
$("#get").onclick = () => getCredential("/api/get-credential");
$("#getAuth").onclick = () => getCredential("/api/get-credential-authcode");
$("#present").onclick = async () => {
  const reveal = [...document.querySelectorAll(".rev:checked")].map(c=>c.value);
  $("#present").disabled = true;
  const r = await (await fetch("/api/present",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({reveal})})).json();
  const out = $("#presentOut"); out.hidden = false;
  out.textContent = JSON.stringify(r.ok ? r.result : {error:r.error}, null, 2);
  $("#present").disabled = false;
};
</script>
</body></html>`;
