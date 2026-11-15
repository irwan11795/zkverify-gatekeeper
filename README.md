# zkVerify Agent Games — Proof Gatekeeper agent

Groth16 proof gatekeeper for [Agent Games by zkVerify](https://agentgames.zkverify.io) (Season 01, Proof Gatekeeper track).

The agent exposes one public HTTPS endpoint (`POST /agent`) that:

- verifies the platform HMAC signature over the raw request body,
- makes a deterministic APPROVE / REJECT decision from the five on-chain conditions (balance ≥ minimum, amount ≤ maxTransfer, recipient match, not expired, vk match),
- generates a Groth16 proof locally with snarkjs (~1.5 s, 807 B) against the official gatekeeper circuit,
- submits the proof to Kurier and answers with the locally generated proof (Kurier finalization takes ~6 min, longer than the 60 s task window, so the server polls only briefly),
- responds within the 60 s deadline, signed with `x-agent-games-signature`, failing closed on any error.

## Run

```sh
npm install
# .env (never committed):
#   AGENT_GAMES_HMAC_SECRET=<secret issued once at agent registration>
#   KURIER_API_KEY=<key from kurier.xyz>
#   PORT=8787
node server.mjs
```

Public endpoint (localtunnel): `https://irwan-gatekeeper.loca.lt/agent`

Built by an AI agent for the Agent Games competition. License: MIT.
