'use strict';
// Approval page. Shows only content that was signed by the guard on the Mac and encrypted
// for this page, and answers with a passkey assertion (user verification required) plus a
// signature by a key that never leaves this browser. Everything is rendered as plain text.
const RELAY = 'https://mb-relay.ryuueda08.workers.dev';
const RP_ID = location.hostname;
const TICKET = /^[A-Za-z0-9_-]{32,64}$/;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();
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
  $('codebox').hidden = !opts.code;
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
  try { d.registered = Boolean((await dbGet('reg')) || (await dbGet('reg-pending'))); } catch (e) { d.registered = 'error: ' + e.name; }
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

const hmacKey = (code) => crypto.subtle.importKey('raw', unb64u(code), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const publicJwk = async (key) => {
  const j = await crypto.subtle.exportKey('jwk', key);
  return { crv: 'P-256', kty: 'EC', x: j.x, y: j.y };
};

async function setup(ticketId) {
  const blob = await getTicket(ticketId);
  if (blob.type !== 'setup') throw new Error('wrong ticket');
  show('この画面を、承認に使う画面として登録します。Macの側に出ている登録コードを貼り付けてください。', { code: true, go: '顔認証で登録する', note: '登録コードは、この画面にだけ貼り付けてください。Museには送らないでください。' });
  $('go').onclick = async () => {
    $('go').disabled = true;
    try {
      const code = $('codeinput').value.trim();
      if (!/^[A-Za-z0-9_-]{43}$/.test(code)) throw new Error('登録コードの形が違います');
      const key = await hmacKey(code);
      // Is this ticket really from the Mac that showed the code?
      const fromMac = await crypto.subtle.verify('HMAC', key, unb64u(blob.tag), enc.encode(canonical({ purpose: 'setup', nonce: blob.nonce, guardId: blob.guardId, macPublicKey: blob.macPublicKey })));
      if (!fromMac) throw new Error('登録コードが合いません');
      const device = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      const receive = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      const deviceJwk = await publicJwk(device.publicKey);
      const encJwk = await publicJwk(receive.publicKey);
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
      const tag = b64u(await crypto.subtle.sign('HMAC', key, enc.encode(canonical({ purpose: 'register', nonce: blob.nonce, guardId: blob.guardId, credentialId, spki, deviceJwk, encJwk }))));
      $('codeinput').value = '';
      // Kept aside until the Mac has accepted it: a failed attempt must not destroy a working registration.
      await dbPut('reg-pending', { credentialId, guardId: blob.guardId, macPublicKey: blob.macPublicKey, deviceKey: device.privateKey, receiveKey: receive.privateKey });
      await postAnswer(ticketId, { type: 'register', credentialId, spki, deviceJwk, encJwk, clientDataJSON: b64u(cred.response.clientDataJSON), authenticatorData: b64u(cred.response.getAuthenticatorData()), tag, diag: await diagnostics() });
      show('登録の合図を送りました。Macの側で確かめが済むと、使えるようになります。');
    } catch (e) {
      $('codeinput').value = '';
      $('go').disabled = false;
      $('note').hidden = false;
      $('note').textContent = '登録できませんでした：' + (e.message || e.name);
    }
  };
}

/** Opens the ticket with the current registration, or with a new one that the Mac has started to use. */
async function openTicket(raw) {
  const reg = await dbGet('reg');
  const pending = await dbGet('reg-pending');
  if (reg && reg.receiveKey) {
    try { return { reg, blob: await unseal(raw, reg) }; } catch (_) { /* maybe the Mac already uses the new one */ }
  }
  if (pending && pending.receiveKey) {
    const blob = await unseal(raw, pending);
    await dbPut('reg', pending);
    await dbPut('reg-pending', null);
    return { reg: pending, blob };
  }
  throw new Error('この画面の登録では開けない中身です');
}

async function unseal(blob, reg) {
  if (blob.type !== 'sealed') throw new Error('not sealed');
  const epkRaw = unb64u(blob.epk);
  const epk = await crypto.subtle.importKey('raw', epkRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: epk }, reg.receiveKey, 256);
  const hk = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: epkRaw, info: enc.encode('mb-seal-v1') }, hk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(blob.iv) }, key, unb64u(blob.ct))));
}

const KIND = { work: '仕事', research: '調べもの', message: '続きの会話' };

/**
 * The texts shown must be exactly the requests that get signed: same number, each hash
 * matched once. Anything missing, extra or repeated means the content was tampered with.
 */
async function matchRequests(payload, details) {
  const want = payload.requestHashes || [];
  const bodies = (details && details.requests) || [];
  if (!Array.isArray(bodies) || bodies.length !== want.length || new Set(want).size !== want.length) return null;
  const left = new Set(want);
  const out = [];
  for (const body of bodies) {
    if (typeof body !== 'string') return null;
    const h = hex(await sha256(body));
    if (!left.delete(h)) return null;
    const r = JSON.parse(body);
    out.push('【' + (KIND[r.kind] || r.kind) + (r.sessionRef ? '・続ける先：' + r.sessionRef : '') + '】\n' + (r.text || ''));
  }
  return left.size === 0 ? out : null;
}

function describe(payload, requests) {
  const lines = [];
  if (payload.purpose === 'unlock') {
    lines.push('操作：鍵を開ける（' + Math.round((payload.durationMs || 0) / 60000) + '分）');
    if (requests.length) {
      lines.push('', '開けると動く依頼（' + requests.length + '件）：');
      requests.forEach((t, i) => lines.push('', (i + 1) + '. ' + t));
    } else lines.push('開けると動く依頼：なし');
  } else {
    lines.push('操作を1件通す');
    lines.push('道具：' + payload.tool);
    for (const k of Object.keys(payload.summary || {})) lines.push(k + '：' + payload.summary[k]);
  }
  lines.push('', '期限：' + new Date(payload.expiresAt).toLocaleTimeString('ja-JP'));
  return lines.join('\n');
}

async function approve(ticketId) {
  const known = (await dbGet('reg')) || (await dbGet('reg-pending'));
  if (!known || !known.receiveKey) {
    // Nothing is sent by itself here: a visitor without a registration cannot use up the ticket.
    show('この画面には登録がありません。', { go: 'この画面の状態を送る', note: '登録したときと同じ開き方で開いてください。' });
    $('go').onclick = async () => {
      $('go').disabled = true;
      try { await postAnswer(ticketId, { type: 'error', where: 'approve', name: 'NoRegistration', diag: await diagnostics() }); show('送りました。'); } catch (_) { show('送れませんでした。'); }
    };
    return;
  }
  const { reg, blob } = await openTicket(await getTicket(ticketId));
  if (blob.type !== 'challenge' || !blob.payload || (blob.payload.purpose !== 'unlock' && blob.payload.purpose !== 'approve')) throw new Error('wrong ticket');
  const payload = blob.payload;
  const macKey = await crypto.subtle.importKey('jwk', reg.macPublicKey, { name: 'Ed25519' }, false, ['verify']);
  const genuine = await crypto.subtle.verify({ name: 'Ed25519' }, macKey, unb64u(blob.macSig), enc.encode(canonical(payload)));
  if (!genuine || payload.guardId !== reg.guardId) { show('中身がMacから来たものか確かめられませんでした。通さないでください。'); return; }
  if (Date.now() >= payload.expiresAt) { show('期限が切れています。もう一度頼み直してください。'); return; }
  let requests = [];
  if (payload.purpose === 'unlock') {
    requests = await matchRequests(payload, blob.details);
    if (!requests) { show('表示する中身と、署名する中身が一致しません。通さないでください。'); return; }
  }
  show('下の中身を読んで、よければ通してください。', { detail: describe(payload, requests), go: '顔認証で通す', no: true, note: 'Museの説明ではなく、ここに出ている中身で決めてください。' });
  const challenge = await sha256(canonical(payload));
  $('go').onclick = async () => {
    $('go').disabled = true;
    try {
      const a = await navigator.credentials.get({ publicKey: { challenge, rpId: RP_ID, allowCredentials: [{ type: 'public-key', id: unb64u(reg.credentialId) }], userVerification: 'required', timeout: 120000 } });
      const deviceSignature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, reg.deviceKey, challenge);
      await postAnswer(ticketId, { type: 'assertion', nonce: payload.nonce, response: {
        credentialId: reg.credentialId,
        authenticatorData: b64u(a.response.authenticatorData),
        clientDataJSON: b64u(a.response.clientDataJSON),
        signature: b64u(a.response.signature),
        deviceSignature: b64u(deviceSignature),
      } });
      show('通しました。Museに戻ってください。');
    } catch (e) {
      $('go').disabled = false;
      $('note').hidden = false;
      $('note').textContent = '通せませんでした：' + (e.message || e.name);
    }
  };
  $('no').onclick = async () => {
    try { await postAnswer(ticketId, { type: 'reject', nonce: payload.nonce }); } catch (_) { /* ignore */ }
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
