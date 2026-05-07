const AUTH_KEY = Deno.env.get("EXIT_NODE_PSK") ?? "CHANGE_ME_TO_A_STRONG_SECRET";
const DEFAULT_AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
const MAX_BATCH = 40;

const SKIP_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding", "proxy-authorization",
  "proxy-connection", "priority", "te"
]);

function base64Encode(buf: Uint8Array): string {
  // chunked encoding for large payloads
  let out = "", i = 0, chunk = 65535;
  for (; i < buf.length; i += chunk) out += String.fromCharCode(...buf.subarray(i, i + chunk));
  return btoa(out);
}

function scrubHeaders(h?: Record<string, string>) {
  const res: Record<string, string> = {};
  for (const k in h) if (!SKIP_HEADERS.has(k.toLowerCase())) res[k] = h[k];
  return res;
}

async function processOne(item: any, selfHost: string): Promise<any> {
  if (!item || typeof item !== "object" || !item.u || typeof item.u !== "string" || !/^https?:\/\//i.test(item.u)) {
    return { e: "bad url" };
  }
  let targetUrl: URL;
  try { targetUrl = new URL(item.u); }
  catch { return { e: "bad url" }; }
  if (targetUrl.hostname === selfHost) return { e: "self-fetch blocked" };

  const headers = new Headers();
  if (item.h && typeof item.h === "object") {
    Object.entries(item.h).forEach(([k, v]) => {
      if (!SKIP_HEADERS.has(k.toLowerCase())) {
        try { headers.set(k, v as string); } catch {}
      }
    });
  }
  headers.set("x-relay-hop", "1");

  const method = (item.m || "GET").toUpperCase();
  const opts: RequestInit = { method, headers, redirect: item.r === false ? "manual" : "follow" };

  // Only attach body for POST/PUT/PATCH, never for GET/HEAD (Worker and Deno differ from browsers)
  if (method !== "GET" && method !== "HEAD" && typeof item.b === "string" && item.b.length > 0) {
    try {
      const binary = Uint8Array.from(atob(item.b), c => c.charCodeAt(0));
      opts.body = binary;
      if (item.ct && !headers.has("content-type")) headers.set("content-type", item.ct);
    } catch { return { e: "bad body base64" }; }
  }

  let resp: Response;
  try { resp = await fetch(targetUrl.toString(), opts); }
  catch (error) { return { e: "fetch failed: "+String(error) }; }

  const buffer = new Uint8Array(await resp.arrayBuffer());
  const base64 = base64Encode(buffer);

  const responseHeaders: Record<string, string> = {};
  resp.headers.forEach((v, k) => { responseHeaders[k] = v; });
  return {
    s: resp.status,
    h: responseHeaders,
    b: base64,
  };
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (AUTH_KEY === DEFAULT_AUTH_KEY) {
    return Response.json({ e: "configure EXIT_NODE_PSK in env" }, { status: 500 });
  }
  if (req.method !== "POST") {
    return Response.json({ e: "method not allowed" }, { status: 405 });
  }
  let body: any;
  try { body = await req.json(); }
  catch { return Response.json({ e: "bad json" }, { status: 400 }); }
  if (!body || body.k !== AUTH_KEY) {
    return Response.json({ e: "unauthorized" }, { status: 401 });
  }
  const selfHost = new URL(req.url).hostname;

  // Batch route
  if (Array.isArray(body.q)) {
    if (body.q.length > MAX_BATCH) return Response.json({ e: "batch too large" }, { status: 400 });
    const results = await Promise.all(body.q.map(
      item => processOne(item, selfHost).catch(e => ({ e: "process err:"+String(e) }))
    ));
    return Response.json({ q: results });
  }
  // Single
  return Response.json(await processOne(body, selfHost));
});
