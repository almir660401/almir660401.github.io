// Static WebAuthn passkey enrollment page (candidate). No network requests, no storage, no keys.
// challenge = base64url(SHA-256(DOMAIN || canonicalJson(ticket)))

export const DOMAIN = "SUPERIA_V27_PRODUCTION_PASSKEY_ENROLLMENT_V1\u0000";
export const TICKET_SCHEMA = "superia.v27.production.passkey-enrollment-ticket.v1";
export const TICKET_KEYS = [
  "expires_at", "git_commit", "issued_at", "origin", "owner_decision_ref", "owner_id",
  "release_hold", "rp_id", "schema", "ticket",
];
const MAX_TICKET_CHARS = 2048;

export function canonicalJson(obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) throw new Error("FLAT_OBJECT_REQUIRED");
  const parts = Object.keys(obj).sort().map((k) => {
    const v = obj[k];
    if (typeof v === "string") {
      if (!/^[\x20-\x7e]*$/.test(v)) throw new Error("ASCII_ONLY");
    } else if (!(typeof v === "boolean" || (typeof v === "number" && Number.isSafeInteger(v)))) {
      throw new Error("STRING_INT_BOOL_ONLY");
    }
    return JSON.stringify(k) + ":" + JSON.stringify(v);
  });
  return "{" + parts.join(",") + "}";
}

export function b64u(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function parseTicket(text) {
  if (typeof text !== "string" || text.length > MAX_TICKET_CHARS) throw new Error("TICKET_SIZE");
  const t = JSON.parse(text);
  const keys = Object.keys(t).sort();
  if (keys.length !== TICKET_KEYS.length || keys.some((k, i) => k !== TICKET_KEYS[i])) throw new Error("TICKET_FIELDS");
  if (t.schema !== TICKET_SCHEMA) throw new Error("TICKET_SCHEMA");
  if (t.release_hold !== true) throw new Error("TICKET_HOLD_REQUIRED");
  canonicalJson(t);
  return t;
}

export async function challengeBytes(ticket, subtle = globalThis.crypto.subtle) {
  if (ticket.schema !== TICKET_SCHEMA) throw new Error("TICKET_SCHEMA");
  const data = new TextEncoder().encode(DOMAIN + canonicalJson(ticket));
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

export async function userHandle(ownerId, subtle = globalThis.crypto.subtle) {
  const data = new TextEncoder().encode("superia-v27-prod-owner:" + String(ownerId));
  return new Uint8Array(await subtle.digest("SHA-256", data)).slice(0, 16);
}

export function checkTicketForPage(ticket, loc, nowSeconds) {
  if (loc.protocol !== "https:") throw new Error("HTTPS_REQUIRED");
  if (ticket.rp_id !== loc.hostname) throw new Error("RP_ID_NOT_THIS_HOST");
  if (ticket.origin !== loc.origin) throw new Error("ORIGIN_NOT_THIS_PAGE");
  if (!(ticket.issued_at <= nowSeconds && nowSeconds < ticket.expires_at)) throw new Error("TICKET_EXPIRED");
}

export function registrationJson(credential) {
  const r = credential.response;
  return {
    client_data_json_b64u: b64u(r.clientDataJSON),
    attestation_object_b64u: b64u(r.attestationObject),
  };
}

function wirePage(doc) {
  const $ = (id) => doc.getElementById(id);
  $("go").addEventListener("click", async () => {
    $("out").textContent = "-";
    try {
      const t = parseTicket($("ticket").value);
      checkTicketForPage(t, window.location, Math.floor(Date.now() / 1000));
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: await challengeBytes(t),
          rp: { id: t.rp_id, name: "Aprovação WebAuthn" },
          user: { id: await userHandle(t.owner_id), name: "owner", displayName: "Proprietário" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          attestation: "none",
          timeout: 180000,
        },
      });
      $("out").textContent = JSON.stringify(registrationJson(credential), null, 2);
    } catch (err) {
      $("out").textContent = "BLOQUEADO: " + (err && err.message ? err.message : String(err));
    }
  });
}

if (typeof document !== "undefined") wirePage(document);
