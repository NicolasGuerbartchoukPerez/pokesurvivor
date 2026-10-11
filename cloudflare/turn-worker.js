/* ============ turn-worker.js — claves TURN para el cooperativo ============
 *
 * Cloudflare Worker (gratis) que da credenciales temporales del TURN de
 * Cloudflare Realtime a los jugadores. Sin TURN, las partidas en grupo que no
 * consiguen conexión directa (datos móviles, algunos routers) se retransmitían
 * por la Realtime Database de Firebase, a 1 $ el GB. Con TURN van por
 * Cloudflare: 1.000 GB gratis al mes y luego 0,05 $ el GB.
 *
 * Sólo se dan credenciales a jugadores con cuenta del juego: el juego manda su
 * token de Firebase y aquí se comprueba (firma de Google, proyecto y caducidad).
 * Así nadie de fuera puede gastar el cupo.
 *
 * Variables del Worker (Settings -> Variables and Secrets, tipo "Secret"):
 *   TURN_KEY_ID         el "Turn Token ID" de Cloudflare Realtime -> TURN
 *   TURN_KEY_API_TOKEN  el "API Token" de esa misma clave
 * Dominio: turn.pokesurvivor.com (Settings -> Domains & Routes -> Custom domain).
 * Ver docs/TURN.md.
 */
const PROJECT = 'pokesurvivor-jpter';
const ORIGINS = ['https://pokesurvivor.com', 'https://www.pokesurvivor.com', 'http://127.0.0.1:8765', 'http://localhost:8765'];
const TTL = 4 * 3600;                         // segundos que valen las credenciales
const JWKS = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

let keys = null, keysAt = 0;                  // claves públicas de Google (caché)

function cors(origin) {
  return {
    'Access-Control-Allow-Origin': ORIGINS.includes(origin) ? origin : ORIGINS[0],
    'Access-Control-Allow-Headers': 'Authorization',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Vary': 'Origin'
  };
}

const b64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));

/** ¿Es un token de Firebase válido de este proyecto? Devuelve el uid o null. */
async function verify(token) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) return null;
  let head, body;
  try { head = JSON.parse(new TextDecoder().decode(b64url(parts[0]))); body = JSON.parse(new TextDecoder().decode(b64url(parts[1]))); }
  catch (e) { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (head.alg !== 'RS256' || body.aud !== PROJECT || body.iss !== 'https://securetoken.google.com/' + PROJECT) return null;
  if (!body.sub || body.exp < now || body.iat > now + 300) return null;
  if (!keys || Date.now() - keysAt > 3600e3) {
    const r = await fetch(JWKS);
    keys = (await r.json()).keys; keysAt = Date.now();
  }
  const jwk = keys.find(k => k.kid === head.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64url(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  return ok ? body.sub : null;
}

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const h = cors(origin);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
    const uid = await verify((req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, ''));
    if (!uid) return new Response(JSON.stringify({ error: 'no autorizado' }), { status: 401, headers: { ...h, 'content-type': 'application/json' } });
    const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + env.TURN_KEY_API_TOKEN, 'content-type': 'application/json' },
      body: JSON.stringify({ ttl: TTL })
    });
    if (!r.ok) return new Response(JSON.stringify({ error: 'turn ' + r.status }), { status: 502, headers: { ...h, 'content-type': 'application/json' } });
    const data = await r.json();
    return new Response(JSON.stringify({ iceServers: data.iceServers, ttl: TTL }), {
      headers: { ...h, 'content-type': 'application/json', 'cache-control': 'no-store' }
    });
  }
};
