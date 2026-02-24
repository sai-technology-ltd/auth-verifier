import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';

const app = createApp({
  forwardedUserIdHeader: 'x-user-id',
  forwardedRoleHeader: 'x-user-role',
  verifyJwt: async (token: string) => {
    if (token === 'good') return { sub: 'user-123', role: 'admin' } as any;
    throw new Error('invalid');
  },
});

test('health returns ok', async () => {
  const res = await request(app).get('/health');
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

test('verify rejects missing bearer token', async () => {
  const res = await request(app).get('/verify');
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'Missing bearer token');
});

test('verify accepts valid bearer token and forwards headers', async () => {
  const res = await request(app).get('/verify').set('Authorization', 'Bearer good');
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
  assert.equal(res.headers['x-user-id'], 'user-123');
  assert.equal(res.headers['x-user-role'], 'admin');
});

test('POST /verify is not exposed', async () => {
  const res = await request(app).post('/verify').send({});
  assert.equal(res.status, 404);
});
