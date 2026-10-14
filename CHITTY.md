---
uri: chittycanon://docs/legal/architecture/chittychronicle
namespace: chittycanon://docs/legal
type: architecture
version: 1.1.0
status: PENDING
registered_with: chittycanon://core/services/canon
title: ChittyChronicle Architecture
certifier: chittycanon://core/services/chittycertify
visibility: INTERNAL
---

# CHITTY — ChittyChronicle

**Canonical service URI:** `chittycanon://core/services/chittychronicle`  
**Domain:** `chronicle.chitty.cc`  
**Tier:** 5 — Application  
**Certification status:** PENDING

## Job to be done

Maintain a matter-scoped timeline/event history with attributable event creation and durable receipts.

## Architecture

```text
authenticated actor/service
        |
        v
 explicit matter/case scope
        |
        v
 Chronicle application API
 POST /api/v1/events
        |
        v
 Neon timeline/event persistence
        |
        +--> matter-scoped retrieval
        +--> trust/proof projections
        +--> downstream dashboards
```

The production Cloudflare Worker is presently an **edge discovery/health projection**, not the application API. It advertises that degraded state through `/api/v1/status`.

## Ecosystem position

| Capability | Relationship |
|---|---|
| ChittyAuth / ChittyID | authenticates caller identity |
| ChittyGov | governs authority to perform material actions |
| ChittyEvidence | owns source evidence and fact lifecycle |
| ChittyLedger | separate ledger capability; Chronicle is not a financial ledger |
| docuMINT / ChittyProof | cryptographic proof projection, not factual truth |
| ChittyRouter | may route events but must not manufacture Chronicle receipts |
| ChittyBeacon | monitors deadlines/events |

## Endpoints

### Edge
- `GET /health`
- `GET /api/v1/status`
- discovery manifests

### Application contract
- `POST /api/v1/events`
- `GET /api/v1/events/:id?caseId=...`
- `POST /api/v1/events/:id/verify?caseId=...`
- `POST /api/v1/events/:id/mint?caseId=...`
- `POST /api/v1/events/:id/certify?caseId=...`

Application endpoints are not considered production-available until the edge/origin route is verified.

## ChittyDNA

ChittyChronicle is an application-layer legal timeline capability. Its event history is downstream of identity/authority and upstream of human-facing chronology/search projections. It must not absorb evidence custody or fact-verification responsibilities.
