import http from "node:http";
import net from "node:net";
import dns from "node:dns/promises";
import crypto from "node:crypto";
import { WebSocketServer, WebSocket } from "ws";

/*
 * Nautica - Hostless.cloud port
 * --------------------------------
 * Cloudflare-specific runtime has been replaced with Node.js:
 *   cloudflare:sockets -> node:net
 *   WebSocketPair      -> ws/noServer
 *   env bindings       -> process.env
 *   CF geo headers     -> normal proxy headers / optional IP lookup
 *
 * Environment variables:
 *   PORT
 *   PROXY_BANK_URL
 *   PROXY_HEALTH_CHECK_API
 *   CONVERTER_URL
 *   UDP_RELAY_HOST
 *   REVERSE_PROXY_TARGET
 *   PUBLIC_HOST (optional; otherwise request Host is used)
 *   APP_NAME (optional)
 */

const PORT = Number(process.env.PORT || 8080);
const PROXY_BANK_URL =
  process.env.PROXY_BANK_URL ||
  "https://raw.githubusercontent.com/papapapapdelesia/Emilia/refs/heads/main/Data/Country-ALIVE.txt";
const PROXY_HEALTH_CHECK_API =
  process.env.PROXY_HEALTH_CHECK_API || "https://cprx-ku6.vercel.app/api/check";
const CONVERTER_URL =
  process.env.CONVERTER_URL || "https://api.foolvpn.me/convert";
const UDP_RELAY_HOST =
  process.env.UDP_RELAY_HOST || "wsudprelay-production.up.railway.app";
const REVERSE_PROXY_TARGET =
  process.env.REVERSE_PROXY_TARGET || "example.com";
const PUBLIC_HOST = process.env.PUBLIC_HOST || "";
const APP_NAME = process.env.APP_NAME || "Nautica Hostless";

const PORTS = [443, 80];
const PROTOCOLS = ["trojan", "vless", "ss"];
const PROXY_PER_PAGE = 20;
const WS_OPEN = WebSocket.OPEN;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Max-Age": "86400",
};

let cachedProxyList = [];
let cachedAt = 0;
let proxyLoadPromise = null;

const REGION_MAP = {
  ASIA: ["ID","SG","MY","PH","TH","VN","JP","KR","CN","HK","TW"],
  SOUTHASIA: ["IN","BD","PK","LK","NP","AF","BT","MV"],
  CENTRALASIA: ["KZ","UZ","TM","KG","TJ"],
  NORTHASIA: ["RU"],
  MIDDLEEAST: ["AE","SA","IR","IQ","JO","IL","YE","SY","OM","KW","QA","BH","LB"],
  CIS: ["RU","UA","BY","KZ","UZ","AM","GE","MD","TJ","KG","TM","AZ"],
  WESTEUROPE: ["FR","DE","NL","BE","AT","CH","IE","LU","MC"],
  EASTEUROPE: ["PL","CZ","SK","HU","RO","BG","MD","UA","BY"],
  NORTHEUROPE: ["SE","FI","NO","DK","EE","LV","LT","IS"],
  SOUTHEUROPE: ["IT","ES","PT","GR","HR","SI","MT","AL","BA","RS","ME","MK"],
  EUROPE: ["FR","DE","NL","BE","AT","CH","IE","LU","MC","PL","CZ","SK","HU","RO","BG","MD","UA","BY","SE","FI","NO","DK","EE","LV","LT","IS","IT","ES","PT","GR","HR","SI","MT","AL","BA","RS","ME","MK"],
  AFRICA: ["ZA","NG","EG","MA","KE","DZ","TN","GH","CI","SN","ET"],
  NORTHAMERICA: ["US","CA","MX"],
  SOUTHAMERICA: ["BR","AR","CL","CO","PE","VE","EC","UY","PY","BO"],
  LATAM: ["MX","BR","AR","CL","CO","PE","VE","EC","UY","PY","BO","CR","GT","PA","DO","HN","NI","SV"],
  AMERICA: ["US","CA","MX","BR","AR","CL","CO","PE","VE","EC"],
  OCEANIA: ["AU","NZ","PG","FJ"],
  GLOBAL: [],
};

function b64urlDecode(s) {
  if (!s) return Buffer.alloc(0);
  try {
    return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  } catch {
    return Buffer.alloc(0);
  }
}

function randomUUID() {
  return crypto.randomUUID();
}

function flag(cc) {
  if (!cc || cc === "XX") return "🌐";
  return [...cc.toUpperCase()]
    .map(c => String.fromCodePoint(127397 + c.charCodeAt(0)))
    .join("");
}

function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function parseProxyText(text) {
  return text.split(/\r?\n/)
    .map(x => x.trim())
    .filter(Boolean)
    .map(line => {
      const [proxyIP, proxyPort, country = "XX", ...orgParts] = line.split(",");
      return {
        proxyIP: (proxyIP || "").trim(),
        proxyPort: (proxyPort || "").trim(),
        country: country.trim().toUpperCase(),
        org: (orgParts.join(",") || "Unknown Org").trim(),
      };
    })
    .filter(p => p.proxyIP && /^\d+$/.test(p.proxyPort));
}

async function getProxyList(force = false) {
  const now = Date.now();
  if (!force && cachedProxyList.length && now - cachedAt < 120_000) {
    return cachedProxyList;
  }
  if (proxyLoadPromise) return proxyLoadPromise;

  proxyLoadPromise = (async () => {
    try {
      const res = await fetch(PROXY_BANK_URL, {
        headers: { "User-Agent": "nautica-hostless/1.0" },
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`Proxy bank HTTP ${res.status}`);
      const parsed = parseProxyText(await res.text());
      if (parsed.length) {
        cachedProxyList = parsed;
        cachedAt = Date.now();
      }
    } catch (e) {
      console.error("[proxy-bank]", e.message);
    } finally {
      proxyLoadPromise = null;
    }
    return cachedProxyList;
  })();

  return proxyLoadPromise;
}

function corsHeaders(extra = {}) {
  return { ...CORS, ...extra };
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, corsHeaders(headers));
  res.end(body);
}

function getPublicHost(req) {
  return PUBLIC_HOST || String(req.headers.host || "").split(":")[0] || "localhost";
}

function parseTarget(text) {
  if (!text) return null;
  let s = String(text).trim().replace(/^\/+/, "");
  const m = s.match(/^(\[[^\]]+\]|[^:]+)[:=-](\d+)$/);
  if (!m) return null;
  return {
    host: m[1].replace(/^\[|\]$/g, ""),
    port: Number(m[2]),
  };
}

function chooseProxyByPath(pathname, proxies) {
  const path = pathname.toUpperCase();

  let m = path.match(/^\/PROXYLIST\/([A-Z]{2}(,[A-Z]{2})*)$/);
  if (m) {
    const countries = m[1].split(",");
    const selected = countries.map(cc => {
      const list = proxies.filter(p => p.country === cc);
      return list.length ? list[Math.floor(Math.random() * list.length)] : null;
    }).filter(Boolean);
    return selected.length ? selected[Math.floor(Math.random() * selected.length)] : null;
  }

  m = path.match(/^\/ALL(\d+)?$/);
  if (m) {
    const idx = m[1] ? Number(m[1]) - 1 : null;
    if (idx === null) return proxies[Math.floor(Math.random() * proxies.length)] || null;
    const grouped = new Map();
    for (const p of proxies) {
      if (!grouped.has(p.country)) grouped.set(p.country, []);
      grouped.get(p.country).push(p);
    }
    const selected = [...grouped.values()].map(list => list[idx]).filter(Boolean);
    return selected.length ? selected[Math.floor(Math.random() * selected.length)] : null;
  }

  m = path.match(/^\/PUTAR(\d+)?$/);
  if (m) {
    const count = Math.max(1, Number(m[1] || 1));
    const countries = shuffle([...new Set(proxies.map(p => p.country))]).slice(0, count);
    const selected = countries.map(cc => {
      const list = proxies.filter(p => p.country === cc);
      return list[Math.floor(Math.random() * list.length)];
    }).filter(Boolean);
    return selected.length ? selected[Math.floor(Math.random() * selected.length)] : null;
  }

  m = path.match(/^\/([A-Z]+)(\d+)?$/);
  if (m && REGION_MAP[m[1]]) {
    const countries = REGION_MAP[m[1]];
    const filtered = m[1] === "GLOBAL"
      ? proxies
      : proxies.filter(p => countries.includes(p.country));
    if (!filtered.length) return null;
    const idx = m[2] ? Number(m[2]) - 1 : null;
    if (idx !== null) return filtered[idx] || null;
    return filtered[Math.floor(Math.random() * filtered.length)];
  }

  m = path.match(/^\/([A-Z]{2})(\d+)?$/);
  if (m) {
    const filtered = proxies.filter(p => p.country === m[1]);
    if (!filtered.length) return null;
    const idx = m[2] ? Number(m[2]) - 1 : 0;
    return filtered[idx] || null;
  }

  return parseTarget(path);
}

function makeConfig(host, proxy, protocol, port, uuid) {
  const target = `${proxy.proxyIP}-${proxy.proxyPort}`;
  const u = new URL(`${protocol}://${host}`);
  u.port = String(port);
  u.searchParams.set("encryption", "none");
  u.searchParams.set("type", "ws");
  u.searchParams.set("host", host);
  u.searchParams.set("security", port === 443 ? "tls" : "none");
  u.searchParams.set("path", `/${target}`);
  u.searchParams.set("sni", port === 80 && protocol === "vless" ? "" : host);

  if (protocol === "ss") {
    u.username = Buffer.from(`none:${uuid}`).toString("base64");
    u.searchParams.set(
      "plugin",
      `v2ray-plugin${port === 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${target};host=${host}`
    );
  } else {
    u.username = uuid;
  }

  u.hash = `${flag(proxy.country)} ${proxy.org} WS ${port === 443 ? "TLS" : "NTLS"}`;
  return u.toString();
}

async function convertConfigs(urls, format) {
  if (format === "raw") return urls.join("\n");
  if (format === "v2ray") return Buffer.from(urls.join("\n")).toString("base64");

  const res = await fetch(CONVERTER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: urls.join(","),
      format,
      template: "cf",
    }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) throw new Error(`converter HTTP ${res.status}`);
  return await res.text();
}

async function subscription(req, res, url) {
  const proxies = await getProxyList();
  const cc = url.searchParams.get("cc");
  const filtered = cc
    ? proxies.filter(p => cc.split(",").map(x => x.toUpperCase()).includes(p.country))
    : proxies;

  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 10)));
  const format = url.searchParams.get("format") || "raw";
  const host = url.searchParams.get("domain") || getPublicHost(req);
  const uuid = randomUUID();

  const urls = [];
  for (const proxy of shuffle([...filtered])) {
    for (const port of PORTS) {
      for (const protocol of PROTOCOLS) {
        if (urls.length >= limit) break;
        urls.push(makeConfig(host, proxy, protocol, port, uuid));
      }
      if (urls.length >= limit) break;
    }
    if (urls.length >= limit) break;
  }

  try {
    const output = await convertConfigs(urls, format);
    send(res, 200, output, { "Content-Type": "text/plain; charset=utf-8" });
  } catch (e) {
    send(res, 502, e.message);
  }
}

async function myIp(req, res) {
  const ip =
    req.headers["cf-connecting-ip"] ||
    req.headers["x-real-ip"] ||
    String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown";

  let geo = {};
  try {
    const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      headers: { "User-Agent": "nautica-hostless/1.0" },
      signal: AbortSignal.timeout(7_000),
    });
    if (r.ok) {
      const x = await r.json();
      geo = {
        country: x.country_name || x.country || null,
        city: x.city || null,
        region: x.region || null,
        asOrganization: x.org || null,
        asn: x.asn || null,
      };
    }
  } catch {}

  send(res, 200, JSON.stringify({ ip, ...geo }), {
    "Content-Type": "application/json",
  });
}

async function healthCheck(req, res, url) {
  const target = url.searchParams.get("target") || "";
  const parsed = parseTarget(target);
  if (!parsed) {
    send(res, 400, JSON.stringify({ proxyip: false, error: "missing target" }), {
      "Content-Type": "application/json",
    });
    return;
  }

  try {
    const r = await fetch(
      `${PROXY_HEALTH_CHECK_API}?ip=${encodeURIComponent(parsed.host + ":" + parsed.port)}`,
      { signal: AbortSignal.timeout(12_000) }
    );
    const data = await r.json();
    send(res, 200, JSON.stringify(data), {
      "Content-Type": "application/json",
    });
  } catch (e) {
    send(res, 502, JSON.stringify({ proxyip: false, error: e.message }), {
      "Content-Type": "application/json",
    });
  }
}

function protocolNameFromUUID(buf) {
  if (buf.length >= 62) {
    const d = buf.subarray(56, 60);
    if (d[0] === 0x0d && d[1] === 0x0a &&
        [1,3,0x7f].includes(d[2]) && [1,3,4].includes(d[3])) {
      return "trojan";
    }
  }

  const uuid = buf.subarray(1, 17).toString("hex");
  if (/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i.test(uuid)) {
    return "vless";
  }

  return "ss";
}

function readIPv4(buf, i) {
  return {
    value: [...buf.subarray(i, i + 4)].join("."),
    next: i + 4,
  };
}

function readIPv6(buf, i) {
  const parts = [];
  for (let n = 0; n < 8; n++) parts.push(buf.readUInt16BE(i + n * 2).toString(16));
  return { value: parts.join(":"), next: i + 16 };
}

function readAddress(buf, i, type) {
  if (type === 1) return readIPv4(buf, i);
  if (type === 3) {
    const len = buf[i];
    return { value: buf.subarray(i + 1, i + 1 + len).toString(), next: i + 1 + len };
  }
  if (type === 4) return readIPv6(buf, i);
  throw new Error(`invalid address type ${type}`);
}

function parseSS(buf) {
  const type = buf[0];
  const a = readAddress(buf, 1, type);
  const portIndex = a.next;
  if (buf.length < portIndex + 2) throw new Error("invalid SS header");
  return {
    protocol: "ss",
    addressRemote: a.value,
    portRemote: buf.readUInt16BE(portIndex),
    rawClientData: buf.subarray(portIndex + 2),
    responseHeader: null,
    isUDP: buf.readUInt16BE(portIndex) === 53,
  };
}

function parseVLESS(buf) {
  if (buf.length < 20) throw new Error("invalid VLESS header");
  const optLen = buf[17];
  const cmd = buf[18 + optLen];
  if (cmd !== 1 && cmd !== 2) throw new Error(`command ${cmd} is not supported`);

  const portIndex = 18 + optLen + 1;
  const port = buf.readUInt16BE(portIndex);
  const type = buf[portIndex + 2];
  const a = readAddress(buf, portIndex + 3, type);

  return {
    protocol: "vless",
    addressRemote: a.value,
    portRemote: port,
    rawClientData: buf.subarray(a.next),
    responseHeader: Buffer.from([buf[0], 0]),
    isUDP: cmd === 2,
  };
}

function parseTrojan(buf) {
  if (buf.length < 64) throw new Error("invalid Trojan header");
  const s = buf.subarray(58);
  if (s.length < 7) throw new Error("invalid Trojan request");
  const cmd = s[0];
  if (cmd !== 1 && cmd !== 3) throw new Error("unsupported Trojan command");

  const type = s[1];
  const a = readAddress(s, 2, type);
  const portIndex = a.next;
  const port = s.readUInt16BE(portIndex);

  return {
    protocol: "trojan",
    addressRemote: a.value,
    portRemote: port,
    rawClientData: s.subarray(portIndex + 4),
    responseHeader: null,
    isUDP: cmd === 3,
  };
}

function parseProtocol(buf) {
  switch (protocolNameFromUUID(buf)) {
    case "vless": return parseVLESS(buf);
    case "trojan": return parseTrojan(buf);
    default: return parseSS(buf);
  }
}

function connectTcp(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port: Number(port) });
    const onError = e => {
      socket.destroy();
      reject(e);
    };
    socket.once("error", onError);
    socket.once("connect", () => {
      socket.removeListener("error", onError);
      resolve(socket);
    });
  });
}

function wsSend(ws, data) {
  if (ws.readyState === WS_OPEN) ws.send(data, { binary: true });
}

async function relayTcp(ws, socket, responseHeader = null) {
  let first = true;

  socket.on("data", chunk => {
    if (first && responseHeader) {
      wsSend(ws, Buffer.concat([responseHeader, chunk]));
      first = false;
    } else {
      wsSend(ws, chunk);
      first = false;
    }
  });

  socket.on("close", () => {
    if (ws.readyState === WS_OPEN) ws.close();
  });

  socket.on("error", () => {
    if (ws.readyState === WS_OPEN) ws.close();
  });

  ws.once("close", () => socket.destroy());
}

function parseRelayEndpoint(host, port) {
  const p = Number(port);
  if (net.isIPv4(host)) {
    return Buffer.from([p >> 8, p & 255, 1, ...host.split(".").map(Number)]);
  }
  if (net.isIPv6(host)) {
    const parts = host.split("::");
    const left = parts[0] ? parts[0].split(":").filter(Boolean) : [];
    const right = parts[1] ? parts[1].split(":").filter(Boolean) : [];
    const words = [...left, ...new Array(8 - left.length - right.length).fill("0"), ...right];
    const out = Buffer.alloc(19);
    out[0] = p >> 8;
    out[1] = p & 255;
    out[2] = 3;
    for (let i = 0; i < 8; i++) out.writeUInt16BE(parseInt(words[i], 16) || 0, 3 + i * 2);
    return out;
  }
  const d = Buffer.from(host);
  return Buffer.concat([Buffer.from([p >> 8, p & 255, 2, d.length]), d]);
}

async function createUdpRelay(ws, targetHost, targetPort, firstPayload, responseHeader) {
  const relayUrl = `wss://${UDP_RELAY_HOST}/`;
  const relay = new WebSocket(relayUrl);

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("UDP relay timeout")), 10_000);
    relay.once("open", () => {
      clearTimeout(timer);
      resolve();
    });
    relay.once("error", e => {
      clearTimeout(timer);
      reject(e);
    });
  });

  const magic = Buffer.from([0x56,0x4c,0x52,0x4c,0x59,0x30,0x30,0x34]);
  const endpoint = parseRelayEndpoint(targetHost, targetPort);
  relay.send(Buffer.concat([magic, Buffer.from([1]), endpoint]));

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("UDP relay ACK timeout")), 5_000);
    const handler = data => {
      const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
      clearTimeout(timer);
      relay.off("message", handler);
      if (b[0] === 0) resolve();
      else reject(new Error("bad UDP relay ACK"));
    };
    relay.on("message", handler);
    relay.once("error", reject);
  });

  if (firstPayload?.length) relay.send(firstPayload);

  let firstBack = true;
  relay.on("message", data => {
    const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (!b.length) return;

    if (firstBack && responseHeader) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(b.length);
      wsSend(ws, Buffer.concat([responseHeader, len, b]));
      firstBack = false;
    } else {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(b.length);
      wsSend(ws, Buffer.concat([len, b]));
      firstBack = false;
    }
  });

  const close = () => {
    try { relay.close(); } catch {}
  };
  relay.on("close", () => {
    if (ws.readyState === WS_OPEN) ws.close();
  });
  ws.once("close", close);
}

function getEarlyData(req) {
  const header = req.headers["sec-websocket-protocol"];
  if (!header) return null;
  const first = String(header).split(",")[0].trim();
  const data = b64urlDecode(first);
  return data.length ? data : null;
}

async function handleWs(ws, req, selectedTarget) {
  let socket = null;
  let buffered = getEarlyData(req);
  let initialized = false;
  let protocolHeader = null;

  const closeAll = () => {
    try { if (socket) socket.destroy(); } catch {}
    try { if (ws.readyState === WS_OPEN) ws.close(); } catch {}
  };

  ws.on("close", closeAll);
  ws.on("error", closeAll);

  const handleChunk = async chunk => {
    if (initialized) {
      if (socket) socket.write(chunk);
      return;
    }

    initialized = true;
    const parsed = parseProtocol(chunk);
    protocolHeader = parsed.responseHeader;

    if (parsed.isUDP) {
      await createUdpRelay(
        ws,
        parsed.addressRemote,
        parsed.portRemote,
        parsed.rawClientData,
        protocolHeader
      );
      return;
    }

    try {
      socket = await connectTcp(parsed.addressRemote, parsed.portRemote);
      socket.write(parsed.rawClientData);
      await relayTcp(ws, socket, protocolHeader);
    } catch (firstError) {
      if (!selectedTarget) throw firstError;

      const target = selectedTarget;
      socket = await connectTcp(target.host, target.port);
      socket.write(parsed.rawClientData);
      await relayTcp(ws, socket, protocolHeader);
    }
  };

  ws.on("message", async data => {
    try {
      const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
      await handleChunk(chunk);
    } catch (e) {
      console.error("[ws]", e.message);
      closeAll();
    }
  });

  if (buffered) {
    try {
      await handleChunk(buffered);
    } catch (e) {
      console.error("[early-data]", e.message);
      closeAll();
    }
  }
}

async function htmlPage(req, url) {
  const proxies = await getProxyList();
  const cc = url.searchParams.get("cc");
  const page = Math.max(0, Number((url.pathname.match(/^\/sub\/(\d+)$/) || [])[1] || 0));
  const list = cc
    ? proxies.filter(p => cc.split(",").includes(p.country))
    : proxies;
  const start = page * PROXY_PER_PAGE;
  const items = list.slice(start, start + PROXY_PER_PAGE);
  const host = getPublicHost(req);

  const cards = items.map((p, i) => {
    const uuid = randomUUID();
    const configs = [
      makeConfig(host, p, "vless", 443, uuid),
      makeConfig(host, p, "trojan", 443, uuid),
      makeConfig(host, p, "ss", 443, uuid),
      makeConfig(host, p, "vless", 80, uuid),
      makeConfig(host, p, "trojan", 80, uuid),
      makeConfig(host, p, "ss", 80, uuid),
    ];
    const buttons = configs.map((c, n) =>
      `<button onclick="navigator.clipboard.writeText(${JSON.stringify(c)})">${["VLESS TLS","Trojan TLS","SS TLS","VLESS NTLS","Trojan NTLS","SS NTLS"][n]}</button>`
    ).join("");
    return `<article><b>${flag(p.country)} ${escapeHtml(p.org)}</b><div>${p.proxyIP}:${p.proxyPort}</div><small>Idle</small><div>${buttons}</div></article>`;
  }).join("");

  const next = start + PROXY_PER_PAGE < list.length ? `<a href="/sub/${page + 1}${cc ? "?cc="+encodeURIComponent(cc) : ""}">Next</a>` : "";
  const prev = page > 0 ? `<a href="/sub/${page - 1}${cc ? "?cc="+encodeURIComponent(cc) : ""}">Prev</a>` : "";

  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(APP_NAME)}</title>
<style>
body{font-family:system-ui;background:#111;color:#eee;margin:0;padding:20px}
a,button{display:inline-block;margin:4px;padding:8px 10px;border-radius:8px;border:1px solid #555;background:#222;color:#eee}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
article{padding:16px;border:1px solid #444;border-radius:14px;background:#181818}
small{display:block;margin:8px 0;color:#aaa}nav{margin:18px 0}
</style></head><body>
<h1>${escapeHtml(APP_NAME)}</h1>
<p>Hostless edition · ${list.length} proxy entries · host: ${escapeHtml(host)}</p>
<nav>${prev} <a href="/sub">Home</a> ${next}</nav>
<main>${cards || "<p>No proxy available.</p>"}</main>
<script>
document.querySelectorAll("article small").forEach((el)=>{
  const text=el.parentElement.innerText.match(/(\\d{1,3}(?:\\.\\d{1,3}){3}:\\d+)/);
  if(!text)return;
  fetch("/check?target="+encodeURIComponent(text[1])).then(r=>r.json()).then(x=>{
    el.textContent=x.proxyip?"Active "+(x.delay||""):"Inactive";
  }).catch(()=>el.textContent="Check failed");
});
</script></body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

async function httpHandler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "OPTIONS") return send(res, 204, "");
  if (url.pathname === "/health") {
    return send(res, 200, JSON.stringify({ ok: true, service: APP_NAME, uptime: process.uptime() }), {
      "Content-Type": "application/json",
    });
  }

  try {
    if (url.pathname === "/api/v1/myip" || url.pathname === "/api/v1/myip/") {
      return myIp(req, res);
    }

    if (url.pathname === "/check") {
      return healthCheck(req, res, url);
    }

    if (url.pathname.startsWith("/api/v1/sub")) {
      return subscription(req, res, url);
    }

    if (url.pathname.startsWith("/sub")) {
      const html = await htmlPage(req, url);
      return send(res, 200, html, { "Content-Type": "text/html; charset=utf-8" });
    }

    if (url.pathname === "/") {
      return send(res, 200, JSON.stringify({
        service: APP_NAME,
        status: "ok",
        endpoints: ["/health", "/sub", "/api/v1/sub", "/api/v1/myip", "/check"],
      }), { "Content-Type": "application/json" });
    }

    // HTTP fallback: preserve the original worker's reverse-proxy behavior.
    const target = process.env.REVERSE_PROXY_TARGET;
    if (target) {
      const targetUrl = new URL(url.toString());
      targetUrl.hostname = target.includes(":") ? target.split(":")[0] : target;
      targetUrl.port = target.includes(":") ? target.split(":")[1] : "443";
      const upstream = await fetch(targetUrl, {
        method: req.method,
        headers: req.headers,
      });
      const body = Buffer.from(await upstream.arrayBuffer());
      res.writeHead(upstream.status, corsHeaders(Object.fromEntries(upstream.headers.entries())));
      return res.end(body);
    }

    return send(res, 404, "Not found");
  } catch (e) {
    console.error("[http]", e);
    return send(res, 500, `An error occurred: ${e.message}`);
  }
}

const server = http.createServer(httpHandler);
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", async (req, socket, head) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const proxies = await getProxyList();
    const selected = chooseProxyByPath(url.pathname, proxies);

    // Only route protocol traffic through websocket paths.
    const isRoute =
      /^\/(PROXYLIST|ALL|PUTAR|ASIA|SOUTHASIA|CENTRALASIA|NORTHASIA|MIDDLEEAST|CIS|WESTEUROPE|EASTEUROPE|NORTHEUROPE|SOUTHEUROPE|EUROPE|AFRICA|NORTHAMERICA|SOUTHAMERICA|LATAM|AMERICA|OCEANIA|GLOBAL)(\d+)?(?:\/|$)/i.test(url.pathname) ||
      /^\/[A-Z]{2}\d*(?:\/|$)/i.test(url.pathname) ||
      !!parseTarget(url.pathname);

    if (!isRoute) {
      socket.destroy();
      return;
    }

    if (!selected) {
      socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, ws => {
      handleWs(ws, req, selected).catch(e => {
        console.error("[upgrade]", e);
        try { ws.close(); } catch {}
      });
    });
  } catch (e) {
    console.error("[upgrade]", e.message);
    try { socket.destroy(); } catch {}
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[nautica-hostless] listening on 0.0.0.0:${PORT}`);
  console.log(`[nautica-hostless] proxy bank: ${PROXY_BANK_URL}`);
});
