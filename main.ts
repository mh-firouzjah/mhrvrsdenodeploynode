/**
 * DomainFront Relay — Deno Deploy
 *
 * TWO modes:
 *   1. Single:  POST { k, m, u, h, b, ct, r }       → { s, h, b }
 *   2. Batch:   POST { k, q: [{m,u,h,b,ct,r}, ...] } → { q: [{s,h,b}, ...] }
 *      Uses Promise.all() — all URLs fetched IN PARALLEL.
 *
 * DEPLOYMENT:
 *   1. Push this file to your Deno Deploy project
 *   2. Change AUTH_KEY below to your own secret
 *   3. Deploy via `deployctl deploy --project=<project-name> relay.ts`
 *
 * CHANGE THE AUTH KEY BELOW TO YOUR OWN SECRET!
 */

const AUTH_KEY = Deno.env.get("EXIT_NODE_PSK") ?? "CHANGE_ME_TO_A_STRONG_SECRET";

// Active-probing defense. When false (production default), bad AUTH_KEY
// requests get a decoy HTML page that looks like a placeholder web app
// instead of the JSON `{"e":"unauthorized"}` body. This makes the
// deployment indistinguishable from a forgotten-but-public web app to
// active scanners that POST malformed payloads looking for proxy endpoints.
//
// Set to `true` during initial setup if a misconfigured client is
// hitting "unauthorized" and you want the explicit JSON error to debug
// — then flip back to false before the deployment is widely shared.
const DIAGNOSTIC_MODE = false;

// Connection-level + IP-leak request headers we strip before forwarding
// to the destination. Browser capability headers (sec-ch-ua*, sec-fetch-*)
// stay intact — modern apps like Google Meet use them for browser gating.
// We also drop the `X-Forwarded-*` / `Forwarded` / `Via` family so a
// misconfigured upstream proxy on the user side can't leak the user's
// real IP through the relay path.
const SKIP_HEADERS: Record<string, number> = {
  host: 1,
  connection: 1,
  "content-length": 1,
  "transfer-encoding": 1,
  "proxy-connection": 1,
  "proxy-authorization": 1,
  priority: 1,
  te: 1,
  "x-forwarded-for": 1,
  "x-forwarded-host": 1,
  "x-forwarded-proto": 1,
  "x-forwarded-port": 1,
  "x-real-ip": 1,
  forwarded: 1,
  via: 1,
};

// Methods we consider safe to replay if batch fetch fails.
// GET/HEAD/OPTIONS are idempotent per RFC 9110; POST/PUT/PATCH/DELETE
// can have side-effects so we surface the error instead of silently
// re-firing them.
const SAFE_REPLAY_METHODS: Record<string, number> = {
  GET: 1,
  HEAD: 1,
  OPTIONS: 1,
};

// ── Type Definitions ────────────────────────────────────

interface SingleRequest {
  k: string;
  m?: string;
  u: string;
  h?: Record<string, string>;
  b?: string;
  ct?: string;
  r?: boolean;
}

interface BatchRequestItem {
  m?: string;
  u: string;
  h?: Record<string, string>;
  b?: string;
  ct?: string;
  r?: boolean;
}

interface BatchRequest {
  k: string;
  q: BatchRequestItem[];
}

interface SingleResponse {
  s: number;
  h: Record<string, string>;
  b: string;
  e?: string;
}

interface BatchResponse {
  q: SingleResponse[];
}

interface FetchResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

// ── Response Helpers ────────────────────────────────────

function _decoyOrError(jsonBody: Record<string, string>): Response {
  return new Response(JSON.stringify(jsonBody), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function _json(obj: Record<string, unknown>): Response {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

// ── Request Handlers ────────────────────────────────────

async function handlePost(request: Request): Promise<Response> {
  try {
    const req = (await request.json()) as SingleRequest | BatchRequest;

    if (req.k !== AUTH_KEY) {
      return _decoyOrError({ e: "unauthorized" });
    }

    // Batch mode: { k, q: [...] }
    if ("q" in req && Array.isArray(req.q)) {
      return await _doBatch(req.q);
    }

    // Single mode
    return await _doSingle(req as SingleRequest);
  } catch (err) {
    // Parse failures of the request body are also probe-shaped — a real
    // client never sends invalid JSON. Decoy for the same reason.
    return _decoyOrError({ e: String(err) });
  }
}

// ── Single Request ─────────────────────────────────────

async function _doSingle(req: SingleRequest): Promise<Response> {
  if (
    !req.u ||
    typeof req.u !== "string" ||
    !req.u.match(/^https?:\/\//i)
  ) {
    return _json({ e: "bad url" });
  }

  const opts = _buildOpts(req);
  const resp = await fetch(req.u, opts);
  const content = await resp.arrayBuffer();

  // Loop guard: if u points at this exit node's own host, refuse.
  // Without this, a misconfigured client could chain exit-node →
  // exit-node → exit-node → ... and burn the host's runtime budget.
  try {
    const reqUrl = new URL(req.u);
    const dstUrl = new URL(resp.url);
    if (
      reqUrl.host === dstUrl.host &&
      reqUrl.protocol === dstUrl.protocol
    ) {
      return Response.json({ e: "exit-node loop refused" }, { status: 400 });
    }
  } catch {
    // Malformed URL — let the fetch below 400.
  }

  return _json({
    s: resp.status,
    h: _respHeaders(resp),
    b: _base64Encode(new Uint8Array(content)),
  });
}

// ── Batch Request ──────────────────────────────────────

async function _doBatch(items: BatchRequestItem[]): Promise<Response> {
  const fetchPromises: Promise<Response | null>[] = [];
  const fetchIndex: number[] = [];
  const fetchMethods: string[] = [];
  const errorMap: Record<number, string> = {};

  for (let i = 0; i < items.length; i++) {
    const item = items[ i ];

    if (!item || typeof item !== "object") {
      errorMap[ i ] = "bad item";
      continue;
    }

    if (
      !item.u ||
      typeof item.u !== "string" ||
      !item.u.match(/^https?:\/\//i)
    ) {
      errorMap[ i ] = "bad url";
      continue;
    }

    try {
      const opts = _buildOpts(item);
      const method = String(item.m || "GET").toUpperCase();
      fetchMethods.push(method);
      fetchIndex.push(i);

      // Create a promise for this fetch
      const promise = fetch(item.u, opts)
        .then((resp) => resp)
        .catch((err) => {
          errorMap[ i ] = String(err);
          return null;
        });

      fetchPromises.push(promise);
    } catch (buildErr) {
      errorMap[ i ] = String(buildErr);
    }
  }

  // Fetch all requests in parallel. If one fails, we still get results
  // for the others thanks to Promise.allSettled (or individual catch handlers).
  let responses: (Response | null)[] = [];

  if (fetchPromises.length > 0) {
    try {
      responses = await Promise.all(fetchPromises);
    } catch (batchErr) {
      // If Promise.all throws, retry safe methods individually
      responses = [];
      for (let j = 0; j < fetchPromises.length; j++) {
        try {
          const method = fetchMethods[ j ];
          if (!SAFE_REPLAY_METHODS[ method ]) {
            errorMap[ fetchIndex[ j ] ] =
              "batch failed; unsafe method not replayed";
            responses[ j ] = null;
            continue;
          }

          const resp = await fetch(
            (items[ fetchIndex[ j ] ].u),
            _buildOpts(items[ fetchIndex[ j ] ])
          );
          responses[ j ] = resp;
        } catch (singleErr) {
          errorMap[ fetchIndex[ j ] ] = String(singleErr);
          responses[ j ] = null;
        }
      }
    }
  }

  const results: SingleResponse[] = [];
  let rIdx = 0;

  for (let i = 0; i < items.length; i++) {
    if (Object.prototype.hasOwnProperty.call(errorMap, i)) {
      results.push({ e: errorMap[ i ], s: 0, h: {}, b: "" });
    } else {
      const resp = responses[ rIdx++ ];
      if (!resp) {
        results.push({ e: "fetch failed", s: 0, h: {}, b: "" });
      } else {
        const content = await resp.arrayBuffer();
        results.push({
          s: resp.status,
          h: _respHeaders(resp),
          b: _base64Encode(new Uint8Array(content)),
        });
      }
    }
  }

  return _json({ q: results });
}

// ── Request Building ───────────────────────────────────

function _buildOpts(req: SingleRequest | BatchRequestItem): RequestInit {
  const opts: RequestInit = {
    method: (req.m || "GET").toLowerCase(),
  };

  if (req.h && typeof req.h === "object") {
    const headers: Record<string, string> = {};
    for (const k in req.h) {
      if (
        req.h.hasOwnProperty(k) &&
        !SKIP_HEADERS[ k.toLowerCase() ]
      ) {
        headers[ k ] = req.h[ k ];
      }
    }
    opts.headers = headers;
  }

  if (req.b) {
    opts.body = _base64Decode(req.b);
    if (req.ct) {
      if (!opts.headers) opts.headers = {};
      if (typeof opts.headers === "object") {
        (opts.headers as Record<string, string>)[ "Content-Type" ] = req.ct;
      }
    }
  }

  if (req.r === false) {
    opts.redirect = "manual";
  }

  return opts;
}

function _respHeaders(resp: Response): Record<string, string> {
  const headers: Record<string, string> = {};
  resp.headers.forEach((value, key) => {
    headers[ key ] = value;
  });
  return headers;
}

// ── Base64 Encoding/Decoding ────────────────────────

function _base64Encode(data: Uint8Array): string {
  return btoa(String.fromCharCode.apply(null, Array.from(data)));
}

function _base64Decode(encoded: string): Uint8Array {
  const binaryString = atob(encoded);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[ i ] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// ── Main Handler ────────────────────────────────────────

async function handleRequest(request: Request): Promise<Response> {
  if (request.method === "POST") {
    return await handlePost(request);
  } else {
    return new Response("Method Not Allowed", { status: 405 });
  }
}

// ── Deno Deploy Entry Point ─────────────────────────────

Deno.serve(handleRequest);
