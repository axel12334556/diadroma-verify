/* Decode detached OpenTimestamps proofs. No Bitcoin verdict here. */
const OTS_MAGIC = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294';
const BTC_TAG = '0588960d73d71901';
const otsHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
function parseOts(b64) {
  if (typeof b64 !== 'string' || b64.length > 90000 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b64) || !b64) throw Error('Invalid base64');
  const data = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  let r = { data, pos: 0 };
  function take(n) { if (!Number.isSafeInteger(n) || n < 0 || r.pos + n > r.data.length) throw Error('Truncated OTS'); const part = r.data.slice(r.pos, r.pos + n); r.pos += n; return part; }
  function one() { return take(1)[0]; }
  function varuint() { let n = 0; for (let shift = 0; shift <= 49; shift += 7) { const x = one(); n += (x & 127) * 2 ** shift; if (!Number.isSafeInteger(n)) throw Error('Oversized integer'); if (x < 128) return n; } throw Error('Oversized integer'); }
  function blob() { return take(varuint()); }
  if (otsHex(take(31)) !== OTS_MAGIC || varuint() !== 1 || one() !== 8) throw Error('Unsupported OTS header');
  const root = take(32);
  const attestations = []; let count = 0;
  function join(a, b) { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; }
  async function walk(msg, depth) {
    if (depth > 256) throw Error('OTS depth limit');
    while (true) {
      if (++count > 10000) throw Error('OTS node limit');
      let tag = one(); const fork = tag === 255; if (fork) tag = one();
      if (tag === 0) {
        const type = otsHex(take(8)); const payload = blob();
        if (type === BTC_TAG) {
          const old = r; const q = { data: payload, pos: 0 };
          r = q; let height; try { height = varuint(); if (q.pos !== q.data.length) throw Error('Trailing attestation data'); } finally { r = old; }
          attestations.push({ digest: otsHex(msg), height });
        }
      } else {
        let next;
        if (tag === 8) next = new Uint8Array(await crypto.subtle.digest('SHA-256', msg));
        else if (tag === 240) next = join(msg, blob());
        else if (tag === 241) next = join(blob(), msg);
        else if (tag === 242) next = msg.slice().reverse();
        else if (tag === 243) next = new TextEncoder().encode(otsHex(msg));
        else throw Error('Unsupported OTS operation');
        if (next.length > 65536) throw Error('OTS message limit');
        await walk(next, depth + 1);
      }
      if (!fork) return;
    }
  }
  return walk(root, 0).then(() => { if (r.pos !== data.length) throw Error('Trailing OTS data'); return { root: otsHex(root), attestations }; });
}
