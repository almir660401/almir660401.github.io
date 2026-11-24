// Static WebAuthn approval page. No network requests, no storage, no keys.
// challenge = base64url(SHA-256(DOMAIN || canonicalJson(statement)))

export const DOMAIN = "SUPERIA_V27_PRODUCTION_CODEPATCH_APPROVAL_V1\u0000";
export const STATEMENT_SCHEMA = "superia.v27.production.codepatch-approval-statement.v1";
export const ASSERTION_SCHEMA = "superia.v27.production.webauthn-assertion.v1";
export const STATEMENT_KEYS = [
  "base_sha256", "credential_id_sha256", "expires_at", "git_commit", "git_repository",
  "issued_at", "job_id", "manifest_sha256", "nonce", "operation", "origin", "owner_id",
  "patch_sha256", "relative_path", "release_id", "rp_id", "schema", "scope_sha256", "target_id",
];
const MAX_STATEMENT_CHARS = 4096;

export function canonicalJson(obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) throw new Error("FLAT_OBJECT_REQUIRED");
  const parts = Object.keys(obj).sort().map((k) => {
    const v = obj[k];
    if (typeof v === "string") {
      if (!/^[\x20-\x7e]*$/.test(v)) throw new Error("ASCII_ONLY");
    } else if (!(typeof v === "number" && Number.isSafeInteger(v))) {
      throw new Error("STRING_OR_INT_ONLY");
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

export function parseStatement(text) {
  if (typeof text !== "string" || text.length > MAX_STATEMENT_CHARS) throw new Error("STATEMENT_SIZE");
  const s = JSON.parse(text);
  const keys = Object.keys(s).sort();
  if (keys.length !== STATEMENT_KEYS.length || keys.some((k, i) => k !== STATEMENT_KEYS[i])) {
    throw new Error("STATEMENT_FIELDS");
  }
  if (s.schema !== STATEMENT_SCHEMA) throw new Error("STATEMENT_SCHEMA");
  canonicalJson(s);
  return s;
}

export async function challengeBytes(statement, subtle = globalThis.crypto.subtle) {
  if (statement.schema !== STATEMENT_SCHEMA) throw new Error("STATEMENT_SCHEMA");
  const data = new TextEncoder().encode(DOMAIN + canonicalJson(statement));
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

export function checkStatementForPage(statement, loc, nowSeconds) {
  if (loc.protocol !== "https:") throw new Error("HTTPS_REQUIRED");
  if (statement.rp_id !== loc.hostname) throw new Error("RP_ID_NOT_THIS_HOST");
  if (statement.origin !== loc.origin) throw new Error("ORIGIN_NOT_THIS_PAGE");
  if (!(statement.issued_at <= nowSeconds && nowSeconds < statement.expires_at)) throw new Error("STATEMENT_EXPIRED");
}

export function assertionJson(credential) {
  const r = credential.response;
  return {
    schema: ASSERTION_SCHEMA,
    credential_id_b64u: b64u(credential.rawId),
    client_data_json_b64u: b64u(r.clientDataJSON),
    authenticator_data_b64u: b64u(r.authenticatorData),
    signature_b64u: b64u(r.signature),
  };
}

function wirePage(doc) {
  const $ = (id) => doc.getElementById(id);
  $("go").addEventListener("click", async () => {
    $("out").textContent = "-";
    $("summary").textContent = "-";
    try {
      const st = parseStatement($("st").value);
      checkStatementForPage(st, window.location, Math.floor(Date.now() / 1000));
      $("summary").textContent = [
        "release: " + st.release_id,
        "alvo: " + st.target_id + " / " + st.relative_path,
        "commit: " + st.git_commit,
        "base -> patch: " + st.base_sha256.slice(0, 12) + " -> " + st.patch_sha256.slice(0, 12),
        "job: " + st.job_id,
        "expira: " + new Date(st.expires_at * 1000).toISOString(),
      ].join("\n");
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: await challengeBytes(st),
          rpId: st.rp_id,
          userVerification: "required",
          timeout: 120000,
          allowCredentials: [],
        },
      });
      $("out").textContent = JSON.stringify(assertionJson(credential), null, 2);
    } catch (err) {
      $("out").textContent = "BLOQUEADO: " + (err && err.message ? err.message : String(err));
    }
  });
}

if (typeof document !== "undefined") wirePage(document);
