import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import {
  requireEventActor,
  requireEventCaseBody,
  requireEventCaseQuery,
} from '../server/middleware/event-authority';

let server: ReturnType<express.Application['listen']>;
let baseUrl: string;

before(async () => {
  const app = express();
  app.use(express.json());

  app.post('/create', requireEventActor, requireEventCaseBody, (req: any, res) => {
    res.json({ actor: req.chittyActorId, caseId: req.body.caseId });
  });
  app.get('/read', requireEventCaseQuery, (req, res) => {
    res.json({ caseId: req.query.caseId });
  });

  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => resolve());
  });
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('Chronicle event authority gates', () => {
  it('rejects event creation without an attributable actor', async () => {
    const res = await fetch(`${baseUrl}/create`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ caseId: 'case-1' }),
    });
    assert.equal(res.status, 400);
    const body = await res.json() as { code: string };
    assert.equal(body.code, 'MISSING_EVENT_ACTOR');
  });

  it('rejects event creation without an explicit matter/case', async () => {
    const res = await fetch(`${baseUrl}/create`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-chitty-actor-id': 'service:test',
      },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
    const body = await res.json() as { code: string };
    assert.equal(body.code, 'MISSING_EVENT_CASE');
  });

  it('propagates the authenticated service actor into the request', async () => {
    const res = await fetch(`${baseUrl}/create`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-chitty-actor-id': 'service:test',
      },
      body: JSON.stringify({ caseId: 'case-1' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json() as { actor: string; caseId: string };
    assert.equal(body.actor, 'service:test');
    assert.equal(body.caseId, 'case-1');
  });

  it('rejects event reads without explicit matter/case scope', async () => {
    const res = await fetch(`${baseUrl}/read`);
    assert.equal(res.status, 400);
    const body = await res.json() as { code: string };
    assert.equal(body.code, 'MISSING_EVENT_CASE');
  });
});
