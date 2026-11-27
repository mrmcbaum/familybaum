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
      const fig = m.querySelector('.gabanner figure'), bar = document.querySelector('.bar .wrap');
      if (fig && bar) { bar.classList.add('withpic'); bar.appendChild(fig); m.querySelector('.gabanner').remove(); }
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
// "Open full size (PDF)" on private pages: wrap the clip's embedded JPEG in a one-page PDF, in the browser
document.addEventListener('click', e => {
  const a = e.target.closest('[data-pdf]'); if (!a) return; e.preventDefault();
  const img = a.closest('.clip').querySelector('img'); const src = img.src;
  if (!src.startsWith('data:image/jpeg')) { window.open(src, '_blank'); return; }
  const bin = atob(src.slice(src.indexOf(',') + 1)); const jpg = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) jpg[i] = bin.charCodeAt(i);
  const w = img.naturalWidth, h = img.naturalHeight, W = (w * .72).toFixed(2), H = (h * .72).toFixed(2);
  const te = new TextEncoder(), parts = [], offs = []; let len = 0;
  const put = x => { const b = typeof x === 'string' ? te.encode(x) : x; parts.push(b); len += b.length; };
  const obj = (n, body, stream) => { offs[n] = len; put(`${n} 0 obj\n${body}\n`); if (stream) { put('stream\n'); put(stream); put('\nendstream\n'); } put('endobj\n'); };
  const cs = te.encode(`q ${W} 0 0 ${H} 0 0 cm /Im0 Do Q`);
  put('%PDF-1.4\n');
  obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
  obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
  obj(3, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>`);
  obj(4, `<< /Type /XObject /Subtype /Image /Width ${w} /Height ${h} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpg.length} >>`, jpg);
  obj(5, `<< /Length ${cs.length} >>`, cs);
  const x = len; put(`xref\n0 6\n0000000000 65535 f \n${offs.slice(1).map(o => String(o).padStart(10, '0') + ' 00000 n \n').join('')}trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${x}\n%%EOF`);
  window.open(URL.createObjectURL(new Blob(parts, { type: 'application/pdf' })), '_blank');
});
