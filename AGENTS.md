# AGENTS.md — ChittyChronicle Developer Guide

## Identity

- Service: `chittychronicle`
- Canonical URI: `chittycanon://core/services/chittychronicle`
- Domain: `chronicle.chitty.cc`
- Tier: 5 — Application
- Current status: PENDING while the application API is not routed through the production edge Worker.

## Commands

```bash
npm ci
npm run check
npm run test:authority
npm run build
```

Run the existing phase-one integration suite only when its required test case/database environment is available:

```bash
npm test
```

## Event-authority rules

1. Event mutations fail closed on authentication.
2. Every event carries explicit matter/case scope; never infer an active case.
3. Every event creator is attributable. Never write `demo-user` in a production authority path.
4. A Chronicle receipt establishes that Chronicle stored an assertion; it does not establish the underlying legal fact.
5. Verification/trust scoring does not replace primary-source fact verification.
6. Reads and derivative actions remain matter-scoped.
7. Never swallow event-delivery failures and report them as successful receipts.
8. Do not create a second event store to compensate for routing failures.
9. Production route, secret, or database changes require a deployment decision/gate.

## Deployment split

- `worker/index.ts` — Cloudflare edge health/discovery surface.
- `server/index.ts` + `server/routes.ts` — Express/Neon application surface.

Do not claim an application endpoint is live merely because it exists in `server/routes.ts`. Verify the production routing path.

## Upstream/downstream boundaries

- Identity/auth: ChittyAuth / ChittyID
- Authority: ChittyGov
- Evidence/facts: ChittyEvidence
- Proof/certificates: docuMINT / ChittyProof / ChittyCert
- Routing: ChittyRouter
- Monitoring: ChittyBeacon

## Review checklist

Before merging Chronicle event changes:

1. `npm run check`
2. `npm run test:authority`
3. build succeeds
4. edge manifest matches actually served endpoints
5. missing credentials fail closed
6. actor and matter identity are required
7. no matter-specific facts are embedded in reusable configuration/docs
8. deployment remains separate from source merge unless explicitly approved
