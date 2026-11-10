'use strict';
// Approval page. Shows only content signed by the guard on the Mac, and answers with a
// passkey assertion (user verification required) plus a signature by a key that never
// leaves this browser. Everything is rendered as plain text.
const RELAY = 'https://mb-relay.ryuueda08.workers.dev';
const RP_ID = location.hostname;
const TICKET = /^[A-Za-z0-9_-]{32,64}$/;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const b64u = (buf) => {
  const b = new Uint8Array(buf);
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64u = (s) => {
  const t = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const a = new Uint8Array(t.length);
  for (let i = 0; i < t.length; i++) a[i] = t.charCodeAt(i);
  return a;
};
const canonical = (v) => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
};
const sha256 = async (d) => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? enc.encode(d) : d));
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const openDb = () => new Promise((resolve, reject) => {
  const r = indexedDB.open('approve-page', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('kv');
  r.onsuccess = () => resolve(r.result);
  r.onerror = () => reject(r.error);
});
const dbGet = async (k) => {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const q = db.transaction('kv').objectStore('kv').get(k);
    q.onsuccess = () => resolve(q.result);
    q.onerror = () => reject(q.error);
  });
};
const dbPut = async (k, v) => {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('kv', 'readwrite');
    tx.objectStore('kv').put(v, k);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
};

function show(status, opts = {}) {
  $('status').textContent = status;
  $('detail').hidden = !opts.detail;
  $('detail').textContent = opts.detail || '';
  $('code').hidden = !opts.code;
  $('code').textContent = opts.code || '';
  $('buttons').hidden = !opts.go;
  $('go').textContent = opts.go || '';
  $('go').disabled = false;
  $('no').hidden = !opts.no;
  $('note').hidden = !opts.note;
  $('note').textContent = opts.note || '';
}

async function diagnostics() {
  const d = { ua: navigator.userAgent, webauthn: typeof PublicKeyCredential !== 'undefined', standalone: navigator.standalone === true };
  try { d.platformAuth = d.webauthn && (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()); } catch (e) { d.platformAuth = 'error: ' + e.name; }
  try { await openDb(); d.idb = true; } catch (e) { d.idb = 'error: ' + e.name; }
  try { d.registered = Boolean(await dbGet('reg')); } catch (e) { d.registered = 'error: ' + e.name; }
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    d.ed25519 = true;
  } catch (e) { d.ed25519 = 'error: ' + e.name; }
  return d;
}

async function getTicket(id) {
  const res = await fetch(RELAY + '/v1/page/tickets/' + id, { cache: 'no-store' });
  if (!res.ok) throw new Error('ticket ' + res.status);
  return JSON.parse((await res.json()).blob);
}
async function postAnswer(id, answer) {
  const res = await fetch(RELAY + '/v1/page/tickets/' + id + '/answer', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ answer: JSON.stringify(answer) }) });
  if (!res.ok) throw new Error('answer ' + res.status);
}

async function sasCode(parts) {
  const h = await sha256(canonical(parts));
  const n = ((h[0] * 16777216) + (h[1] << 16) + (h[2] << 8) + h[3]) >>> 0;
  return String(n % 1000000).padStart(6, '0');
}

async function setup(ticketId) {
  const blob = await getTicket(ticketId);
  if (blob.type !== 'setup') throw new Error('wrong ticket');
  const diag = await diagnostics();
  show('この画面を、承認に使う画面として登録します。', { go: '顔認証で登録する', note: '登録のあとに6けたの数字が出ます。Macの側の数字と同じかを確かめます。' });
  $('go').onclick = async () => {
    $('go').disabled = true;
    try {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      const full = await crypto.subtle.exportKey('jwk', pair.publicKey);
      const deviceJwk = { crv: 'P-256', kty: 'EC', x: full.x, y: full.y };
      const challenge = await sha256(canonical({ v: 1, purpose: 'register', nonce: blob.nonce, guardId: blob.guardId }));
      const cred = await navigator.credentials.create({ publicKey: {
        rp: { id: RP_ID, name: '承認ページ' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'owner', displayName: 'owner' },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none',
        timeout: 120000,
      } });
      const credentialId = b64u(cred.rawId);
      const spki = b64u(cred.response.getPublicKey());
      const code = await sasCode({ credentialId, spki, deviceJwk, macPublicKey: blob.macPublicKey, nonce: blob.nonce });
      await dbPut('reg', { credentialId, guardId: blob.guardId, macPublicKey: blob.macPublicKey, deviceKey: pair.privateKey });
      await postAnswer(ticketId, { type: 'register', credentialId, spki, deviceJwk, clientDataJSON: b64u(cred.response.clientDataJSON), authenticatorData: b64u(cred.response.getAuthenticatorData()), diag });
      show('登録の合図を送りました。この数字を、Macの側の数字と見比べてください。', { code });
    } catch (e) {
      try { await postAnswer(ticketId, { type: 'error', where: 'setup', name: e.name, message: String(e.message).slice(0, 200), diag }); } catch (_) { /* ticket may be gone */ }
      show('登録できませんでした。', { detail: e.name + ': ' + e.message });
    }
  };
}

function describe(blob, verifiedRequests) {
  const p = blob.payload;
  const lines = [];
  if (p.purpose === 'unlock') {
    lines.push('操作：鍵を開ける（' + Math.round((p.durationMs || 0) / 60000) + '分）');
    if (verifiedRequests.length) {
      lines.push('', '待っている依頼：');
      verifiedRequests.forEach((t, i) => lines.push((i + 1) + '. ' + t));
    } else lines.push('待っている依頼：なし');
  } else {
    lines.push('操作を1件通す');
    lines.push('道具：' + p.tool);
    for (const k of Object.keys(p.summary || {})) lines.push(k + '：' + p.summary[k]);
  }
  lines.push('', '期限：' + new Date(p.expiresAt).toLocaleTimeString('ja-JP'));
  return lines.join('\n');
}

async function approve(ticketId) {
  const diag = await diagnostics();
  const reg = await dbGet('reg');
  if (!reg) {
    try { await postAnswer(ticketId, { type: 'error', where: 'approve', name: 'NoRegistration', diag }); } catch (_) { /* ignore */ }
    show('この画面には登録がありません。', { note: '登録したときと同じ開き方で開いてください。' });
    return;
  }
  const blob = await getTicket(ticketId);
  if (blob.type !== 'challenge') throw new Error('wrong ticket');
  const macKey = await crypto.subtle.importKey('jwk', reg.macPublicKey, { name: 'Ed25519' }, false, ['verify']);
  const genuine = await crypto.subtle.verify({ name: 'Ed25519' }, macKey, unb64u(blob.macSig), enc.encode(canonical(blob.payload)));
  if (!genuine || blob.payload.guardId !== reg.guardId) {
    show('中身がMacから来たものか確かめられませんでした。通さないでください。');
    return;
  }
  if (Date.now() >= blob.payload.expiresAt) { show('期限が切れています。もう一度頼み直してください。'); return; }
  // Request texts are shown only if their hash is part of what will be signed.
  const verified = [];
  for (const body of (blob.details && blob.details.requests) || []) {
    if ((blob.payload.requestHashes || []).includes(hex(await sha256(body)))) {
      const r = JSON.parse(body);
      verified.push(r.text || r.keyword || r.kind);
    }
  }
  show('下の中身を読んで、よければ通してください。', { detail: describe(blob, verified), go: '顔認証で通す', no: true, note: 'Museの説明ではなく、ここに出ている中身で決めてください。' });
  const challenge = await sha256(canonical(blob.payload));
  $('go').onclick = async () => {
    $('go').disabled = true;
    try {
      const a = await navigator.credentials.get({ publicKey: { challenge, rpId: RP_ID, allowCredentials: [{ type: 'public-key', id: unb64u(reg.credentialId) }], userVerification: 'required', timeout: 120000 } });
      const deviceSignature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, reg.deviceKey, challenge);
      await postAnswer(ticketId, { type: 'assertion', nonce: blob.payload.nonce, diag, response: {
        credentialId: reg.credentialId,
        authenticatorData: b64u(a.response.authenticatorData),
        clientDataJSON: b64u(a.response.clientDataJSON),
        signature: b64u(a.response.signature),
        deviceSignature: b64u(deviceSignature),
      } });
      show('通しました。Museに戻ってください。');
    } catch (e) {
      try { await postAnswer(ticketId, { type: 'error', where: 'approve', name: e.name, message: String(e.message).slice(0, 200), diag }); } catch (_) { /* ignore */ }
      show('通せませんでした。', { detail: e.name + ': ' + e.message });
    }
  };
  $('no').onclick = async () => {
    try { await postAnswer(ticketId, { type: 'reject', nonce: blob.payload.nonce }); } catch (_) { /* ignore */ }
    show('通しませんでした。');
  };
}

(async () => {
  const params = new URLSearchParams(location.hash.slice(1));
  const s = params.get('s');
  const t = params.get('t');
  try {
    if (s && TICKET.test(s)) await setup(s);
    else if (t && TICKET.test(t)) await approve(t);
    else show('いま確認が必要なものはありません。', { note: 'Museの会話に出たリンクから開いてください。' });
  } catch (e) {
    show('読み込めませんでした。リンクの期限が切れているかもしれません。', { detail: e.name + ': ' + e.message });
  }
})();
