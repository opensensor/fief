import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

export async function registerPasskey(beginUrl, finishUrl) {
    const optionsResp = await fetch(beginUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
    });
    if (!optionsResp.ok) throw new Error('begin failed');
    const options = await optionsResp.json();
    const attestation = await startRegistration(options);
    const finishResp = await fetch(finishUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(attestation),
    });
    if (!finishResp.ok) throw new Error('finish failed');
    return await finishResp.json();
}

// For 2FA challenge: options are embedded server-side, no /begin fetch
export async function authenticateWithEmbeddedOptions(options, finishUrl) {
    const assertion = await startAuthentication(options);
    const finishResp = await fetch(finishUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(assertion),
    });
    if (!finishResp.ok) throw new Error('verify failed');
    return await finishResp.json();
}
