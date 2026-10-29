import assert from 'node:assert/strict';
import { afterEach, test, mock } from 'node:test';
import { registerPasskey, authenticateWithEmbeddedOptions } from './webauthn.mjs';

const buffer = () => new Uint8Array([1, 2, 3]).buffer;
const options = {
  challenge: 'AQID',
  rp: { id: 'example.test', name: 'Test' },
  user: { id: 'AQID', name: 'test@example.test', displayName: 'Test' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
};
const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
afterEach(() => {
  mock.restoreAll();
  Object.defineProperty(globalThis, 'navigator', originalNavigator);
  delete globalThis.PublicKeyCredential;
});

function authenticator(method) {
  globalThis.PublicKeyCredential = class {};
  const invoke = mock.fn(async ({ publicKey }) => {
    assert.deepEqual(new Uint8Array(publicKey.challenge), new Uint8Array([1, 2, 3]));
    return {
      id: 'AQID', rawId: buffer(), type: 'public-key',
      getClientExtensionResults: () => ({}),
      response: {
        attestationObject: buffer(), clientDataJSON: buffer(),
        authenticatorData: buffer(), signature: buffer(),
      },
    };
  });
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true, value: { credentials: { [method]: invoke } },
  });
  return invoke;
}

test('registration sends the authenticator result to the same-origin finish endpoint', async () => {
  const create = authenticator('create');
  const fetch = mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.method, 'POST');
    if (url === '/begin') return Response.json(options);
    assert.equal(url, '/finish');
    assert.equal(JSON.parse(init.body).response.attestationObject, 'AQID');
    return Response.json({ registered: true });
  });
  assert.deepEqual(await registerPasskey('/begin', '/finish'), { registered: true });
  assert.equal(create.mock.callCount(), 1);
  assert.equal(fetch.mock.callCount(), 2);
});

test('authentication serializes an assertion from the current WebAuthn library', async () => {
  const get = authenticator('get');
  mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, '/verify');
    assert.equal(init.credentials, 'same-origin');
    assert.equal(JSON.parse(init.body).response.signature, 'AQID');
    return Response.json({ verified: true });
  });
  assert.deepEqual(await authenticateWithEmbeddedOptions(options, '/verify'), { verified: true });
  assert.equal(get.mock.callCount(), 1);
});

test('a rejected begin request never invokes the authenticator', async () => {
  const create = authenticator('create');
  mock.method(globalThis, 'fetch', async () => new Response('', { status: 403 }));
  await assert.rejects(registerPasskey('/begin', '/finish'), /begin failed/);
  assert.equal(create.mock.callCount(), 0);
});

test('a rejected assertion response is surfaced to the caller', async () => {
  authenticator('get');
  mock.method(globalThis, 'fetch', async () => new Response('', { status: 400 }));
  await assert.rejects(authenticateWithEmbeddedOptions(options, '/verify'), /verify failed/);
});
