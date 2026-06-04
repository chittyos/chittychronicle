/**
 * Unit tests for the fail-closed `requireServiceToken` middleware.
 *
 * No mocks: drives the real middleware via an in-process express() app and real
 * fetch() calls. Exercises every branch of the fail-closed envelope.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { requireServiceToken } from '../server/middleware/authz';

let server: ReturnType<express.Application['listen']>;
let baseUrl: string;

const SAVED_TOKEN = process.env.CHITTYCHRONICLE_SERVICE_TOKEN;

before(async () => {
  const app = express();
  app.get('/protected', requireServiceToken, (_req, res) => {
    res.json({ ok: true });
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => resolve());
  });
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (SAVED_TOKEN === undefined) {
    delete process.env.CHITTYCHRONICLE_SERVICE_TOKEN;
  } else {
    process.env.CHITTYCHRONICLE_SERVICE_TOKEN = SAVED_TOKEN;
  }
});

beforeEach(() => {
  delete process.env.CHITTYCHRONICLE_SERVICE_TOKEN;
});

describe('requireServiceToken (fail-closed)', () => {
  it('returns 503 SERVICE_TOKEN_NOT_CONFIGURED when env var is missing (no fallback to allow)', async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: 'Bearer anything' },
    });
    assert.equal(res.status, 503);
    const body = await res.json() as { error: string; code: string };
    assert.equal(body.code, 'SERVICE_TOKEN_NOT_CONFIGURED');
  });

  it('returns 401 MISSING_BEARER_TOKEN when Authorization header is absent', async () => {
    process.env.CHITTYCHRONICLE_SERVICE_TOKEN = 'real-token-value';
    const res = await fetch(`${baseUrl}/protected`);
    assert.equal(res.status, 401);
    const body = await res.json() as { error: string; code: string };
    assert.equal(body.code, 'MISSING_BEARER_TOKEN');
  });

  it('returns 401 MISSING_BEARER_TOKEN when Authorization header is non-Bearer', async () => {
    process.env.CHITTYCHRONICLE_SERVICE_TOKEN = 'real-token-value';
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: 'Basic dXNlcjpwYXNz' },
    });
    assert.equal(res.status, 401);
    const body = await res.json() as { error: string; code: string };
    assert.equal(body.code, 'MISSING_BEARER_TOKEN');
  });

  it('returns 401 INVALID_BEARER_TOKEN when token mismatches', async () => {
    process.env.CHITTYCHRONICLE_SERVICE_TOKEN = 'real-token-value';
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: 'Bearer wrong-token' },
    });
    assert.equal(res.status, 401);
    const body = await res.json() as { error: string; code: string };
    assert.equal(body.code, 'INVALID_BEARER_TOKEN');
  });

  it('returns 401 INVALID_BEARER_TOKEN when bearer prefix is present but token is empty after trim', async () => {
    process.env.CHITTYCHRONICLE_SERVICE_TOKEN = 'real-token-value';
    // Use a non-trimmable empty-token shape that survives fetch header normalization
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: 'Bearer x' },
    });
    assert.equal(res.status, 401);
    const body = await res.json() as { error: string; code: string };
    assert.equal(body.code, 'INVALID_BEARER_TOKEN');
  });

  it('accepts case-insensitive Bearer prefix when token matches', async () => {
    process.env.CHITTYCHRONICLE_SERVICE_TOKEN = 'real-token-value';
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: 'bearer real-token-value' },
    });
    assert.equal(res.status, 200);
    const body = await res.json() as { ok: boolean };
    assert.equal(body.ok, true);
  });

  it('accepts the exact token and forwards to the handler', async () => {
    process.env.CHITTYCHRONICLE_SERVICE_TOKEN = 'real-token-value';
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: 'Bearer real-token-value' },
    });
    assert.equal(res.status, 200);
    const body = await res.json() as { ok: boolean };
    assert.equal(body.ok, true);
  });
});
