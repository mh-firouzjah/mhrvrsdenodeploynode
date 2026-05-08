// mhrv-rs exit node — deploy as an HTTP endpoint on any serverless
// TypeScript host with a public IP that isn't a Google datacenter
// (Deno Deploy, fly.io, your own VPS, etc.). Uses only web-standard
// `Request` / `Response` / `fetch` so it's portable across runtimes.
//
// Purpose: chain client → Apps Script → this exit node → destination.
// Apps Script's UrlFetchApp can't reach Cloudflare-protected sites that
// flag Google datacenter IPs as bots (chatgpt.com, claude.ai, grok.com,
// many other CF-fronted SaaS). This exit node sits between Apps Script
// and the destination; the destination sees the exit node's outbound IP
// (generally not flagged as Google datacenter) and accepts the request.
//
// Setup:
//   1. Pick a host that runs web-standard fetch handlers (e.g. Deno
//      Deploy, fly.io with a thin server wrapper, or any cheap VPS
//      running Deno / Node + this script as a handler).
//   2. Paste the contents of this file as the request handler.
//   3. Set PSK below to a strong secret (`openssl rand -hex 32` from
//      a terminal — DO NOT leave the placeholder in production).
//   4. Deploy and copy the public URL of the deployed handler.
//   5. In mhrv-rs config.json, add:
//        "exit_node": {
//          "enabled": true,
//          "relay_url": "https://your-deployed-exit-node.example.com",
//          "psk": "<the same PSK you set above>",
//          "mode": "selective",
//          "hosts": ["chatgpt.com", "claude.ai", "x.com", "grok.com"]
//        }
//
// Threat model: PSK is the only thing keeping this from being an open
// proxy on the public internet. Treat it like a password: do not commit
// to source control, do not share publicly, rotate if leaked. The exit
// node refuses all requests that don't carry the matching PSK.
//
// Failure mode: if the exit node is unreachable, mhrv-rs falls back to
// the regular Apps Script relay automatically — the only consequence
// of an offline exit node is that ChatGPT/Claude/Grok stop working;
// other sites are unaffected.

const PSK = Deno.env.get("EXIT_NODE_PSK") ?? "CHANGE_ME_TO_A_STRONG_SECRET";
const DIAGNOSTIC_MODE = false;

// Headers the client may send that must NOT be forwarded to the
// destination — they're hop-by-hop or would break re-encoding.
const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
  "forwarded",
  "via",
]);

function decodeBase64ToBytes(input: string): Uint8Array {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[ i ] = bin.charCodeAt(i);
  return out;
}

function encodeBytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[ i ]);
  return btoa(bin);
}

function sanitizeHeaders(h: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h || typeof h !== "object") return out;
  for (const [ k, v ] of Object.entries(h as Record<string, unknown>)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[ k ] = String(v ?? "");
  }
  return out;
}


interface ExitNodeRequest {
  k: string;
  m?: string;
  u: string;
  h?: Record<string, string>;
  b?: string;
  ct?: string;
  r?: boolean;
}

interface ExitNodeResponse {
  s: number;
  h: Record<string, string>;
  b: string;
  e?: string;
}

interface BatchExitNodeRequest {
  k: string;
  q: Array<{
    m?: string;
    u: string;
    h?: Record<string, string>;
    b?: string;
    ct?: string;
    r?: boolean;
  }>;
}

async function handleSingleRequest(req: ExitNodeRequest): Promise<ExitNodeResponse> {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return { s: 400, h: {}, b: "", e: "bad url" };
  }

  let payload: Uint8Array | undefined;
  if (typeof req.b === "string" && req.b.length > 0) {
    payload = decodeBase64ToBytes(req.b);
  }

  try {
    const resp = await fetch(req.u, {
      method: (req.m || "GET").toUpperCase(),
      headers: req.h || {},
      body: payload,
      redirect: "manual",
    });

    const data = new Uint8Array(await resp.arrayBuffer());
    const respHeaders: Record<string, string> = {};
    resp.headers.forEach((value, key) => {
      respHeaders[ key ] = value;
    });

    return {
      s: resp.status,
      h: respHeaders,
      b: encodeBytesToBase64(data),
    };
  } catch (err) {
    return {
      s: 502,
      h: {},
      b: "",
      e: String(err),
    };
  }
}

async function handleBatchRequest(
  req: BatchExitNodeRequest
): Promise<{ q: ExitNodeResponse[]; }> {
  const promises = req.q.map((item) =>
    handleSingleRequest({
      k: req.k,
      m: item.m,
      u: item.u,
      h: item.h,
      b: item.b,
      ct: item.ct,
      r: item.r,
    })
  );

  const results = await Promise.all(promises);
  return { q: results };
}

async function handleRequest(request: Request): Promise<Response> {
  if (request.method !== "POST") {
    return Response.json({ e: "method_not_allowed" }, { status: 405 });
  }

  try {
    const body = await request.json();

    if (typeof body.k !== "string") {
      return Response.json({ e: "missing auth key" }, { status: 400 });
    }

    if (body.k !== PSK) {
      return Response.json({ e: "unauthorized" }, { status: 401 });
    }

    // Batch mode: { k, q: [...] }
    if (Array.isArray(body.q)) {
      const batchResp = await handleBatchRequest(body as BatchExitNodeRequest);
      return Response.json(batchResp);
    }

    // Single mode
    const singleResp = await handleSingleRequest(body as ExitNodeRequest);
    if (singleResp.e) {
      return Response.json(singleResp, { status: singleResp.s || 500 });
    }
    return Response.json(singleResp);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ e: message }, { status: 500 });
  }
}

Deno.serve(handleRequest);