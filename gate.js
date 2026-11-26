{
const B = JSON.parse(document.getElementById('blob').textContent);
const u8 = b => Uint8Array.from(atob(b), c => c.charCodeAt(0));
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
const S = crypto.subtle, KEY = 'familybaum-keys';
const err = document.getElementById('err');
function stored() { try { return JSON.parse(localStorage.getItem(KEY) || '[]') } catch (_) { return [] } }
function store(k) { try { const a = stored(); if (!a.includes(k)) { a.push(k); localStorage.setItem(KEY, JSON.stringify(a)) } } catch (_) {} }
async function derive(pw) {
  const k0 = await S.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  return S.deriveBits({ name: 'PBKDF2', salt: u8(B.salt), iterations: B.n, hash: 'SHA-256' }, k0, 256);
}
async function tryKey(raw) {
  const kp = await S.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  for (const w of B.wraps) {
    try {
      const ck = await S.decrypt({ name: 'AES-GCM', iv: u8(w.iv) }, kp, u8(w.c));
      const k = await S.importKey('raw', ck, 'AES-GCM', false, ['decrypt']);
      const pt = await S.decrypt({ name: 'AES-GCM', iv: u8(B.iv) }, k, u8(B.c));
      const m = document.getElementById('site');
      m.innerHTML = new TextDecoder().decode(pt); m.hidden = false;
      document.getElementById('gate').hidden = true;
      return true;
    } catch (_) {}
  }
  return false;
}
(async () => { for (const k of stored()) { if (await tryKey(u8(k))) return } })();
document.getElementById('gf').addEventListener('submit', async e => {
  e.preventDefault(); err.textContent = 'Checking…';
  const raw = await derive(document.getElementById('pw').value);
  if (await tryKey(raw)) { err.textContent = ''; if (document.getElementById('rem').checked) store(b64(raw)) }
  else err.textContent = 'That password doesn’t open this page. It may belong to a different branch of the family.';
});
document.getElementById('forget').addEventListener('click', e => { try { localStorage.removeItem(KEY) } catch (_) {} e.target.textContent = 'Forgotten on this device' });
document.addEventListener('click', async e => { const b = e.target.closest('[data-copy]'); if (!b) return;
  try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copied' } catch (_) { b.textContent = b.dataset.copy } });
}
