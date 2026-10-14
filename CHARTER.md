---
uri: chittycanon://docs/legal/policy/chittychronicle-charter
namespace: chittycanon://docs/legal
type: policy
version: 1.1.0
status: PENDING
registered_with: chittycanon://core/services/canon
title: ChittyChronicle Service Charter
certifier: chittycanon://core/services/chittycertify
visibility: INTERNAL
---

# ChittyChronicle Service Charter

**Canonical service URI:** `chittycanon://core/services/chittychronicle`  
**Domain:** `chronicle.chitty.cc`  
**Tier:** 5 — Application

## Mission

ChittyChronicle provides matter-scoped legal timeline and event-history capabilities. It records and projects events; it does not independently establish the truth of an underlying evidentiary assertion.

## Ownership boundary

ChittyChronicle owns:

- matter-scoped timeline entries and event-history projections;
- Chronicle event receipt persistence in its canonical application database;
- retrieval of Chronicle events within an explicit matter scope.

ChittyChronicle does **not** own:

- evidence bytes or custody identity — ChittyEvidence;
- factual verification lifecycle — fact governance / ChittyEvidence;
- business/legal authority — ChittyGov;
- identity authentication — ChittyAuth / ChittyID;
- cryptographic document proof or certification — docuMINT / ChittyProof / ChittyCert.

An event receipt proves that Chronicle recorded an event assertion. It does not, by itself, prove that the asserted event occurred.

## Authentication and matter isolation

Event-authority mutation routes fail closed. A valid service credential, explicit actor identity, and explicit matter/case identity are required. Missing authentication or matter identity is an error, never an implicit default.

## Surfaces

### Production edge surface

The Cloudflare Worker at `chronicle.chitty.cc` currently serves only:

- `GET /health`
- `GET /api/health`
- `GET /api/v1/status`
- discovery manifests

The application API is **not currently routed through the production edge Worker**. Application requests return a degraded/not-routed response. This charter therefore remains `PENDING`.

### Canonical application event contract

The full application defines:

- `POST /api/v1/events` — create a matter-scoped event
- `GET /api/v1/events/:id?caseId=...` — read within explicit matter scope
- `POST /api/v1/events/:id/verify?caseId=...`
- `POST /api/v1/events/:id/mint?caseId=...`
- `POST /api/v1/events/:id/certify?caseId=...`

Production routing to those handlers must be separately verified before any downstream service treats Chronicle delivery as durable.

## Dependencies

- ChittyID / ChittyAuth — identity and authentication
- ChittyConnect — service integration
- ChittyBeacon — deadline/event monitoring
- Neon PostgreSQL — Chronicle application persistence
- ChittyGov — authority decisions when an event represents a governed action

## Legal/evidence invariants

1. Chronicle events are matter-scoped.
2. Search or model inference never converts an event assertion into a verified legal fact.
3. Event authorship is attributable; `demo-user` and anonymous production authorship are prohibited.
4. A failed Chronicle delivery remains visible as a failed receipt.
5. Timeline state never substitutes for the primary source instrument.
6. Source evidence is not destructively modified by Chronicle.
