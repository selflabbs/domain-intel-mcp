/**
 * Datakoot Domain & Company Intel MCP Server
 * Remote MCP server (Streamable HTTP, stateless) for Cloudflare Workers.
 * Zero dependencies, zero API keys. All data from free public sources.
 *
 * Tools:
 *   domain_intel        — registration data via RDAP (registrar, dates, status, nameservers, age)
 *   dns_lookup          — A/AAAA/MX/NS/TXT/CNAME/SOA via Cloudflare DoH
 *   email_deliverability— MX presence + SPF/DMARC posture, free/disposable detection
 *   tech_stack          — homepage fingerprint: server, CMS/framework, CDN, analytics
 *   subdomains          — certificate-transparency subdomain discovery (crt.sh)
 */

const SERVER_INFO = { name: "domain-intel", version: "1.0.0" };
const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const TOOLS = [
  { name: "domain_report", description: "One-call full dossier on a domain: registration (RDAP), DNS records, email deliverability, and website tech stack, combined into a single report. Use for fast lead qualification, company research, or recon without four separate calls.", inputSchema: { type: "object", properties: { domain: { type: "string", description: "Domain name, e.g. stripe.com" } }, required: ["domain"] } },
  {
    name: "domain_intel",
    description:
      "Registration intelligence for a domain via RDAP (the modern WHOIS). Returns registrar, creation/expiration/last-changed dates, domain age in years, EPP status codes, nameservers, DNSSEC state, and abuse contact. Use to vet a company, assess a lead, or judge how established a domain is.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name, e.g. stripe.com (no scheme)" } },
      required: ["domain"],
    },
  },
  {
    name: "dns_lookup",
    description:
      "Look up DNS records for a domain via Cloudflare DNS-over-HTTPS. Returns A, AAAA, MX, NS, TXT, CNAME, and SOA records. Use to see where a domain is hosted, who runs its mail and DNS, and what verification/policy TXT records it publishes.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domain name, e.g. stripe.com" },
        types: {
          type: "array",
          items: { type: "string" },
          description: "Optional subset of record types, e.g. [\"MX\",\"TXT\"]. Defaults to all common types.",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "email_deliverability",
    description:
      "Assess whether a domain (or the domain of an email address) can receive mail and how strong its sender authentication is. Returns MX presence, SPF and DMARC policy, whether it's a free consumer provider (gmail, etc.) or a known disposable/temp-mail provider, and an overall verdict. Use to qualify leads and flag throwaway signups.",
    inputSchema: {
      type: "object",
      properties: {
        domain_or_email: { type: "string", description: "A domain (stripe.com) or an email address (a@stripe.com)" },
      },
      required: ["domain_or_email"],
    },
  },
  {
    name: "tech_stack",
    description:
      "Fingerprint the technology behind a website by fetching its homepage. Detects web server, CMS/framework (WordPress, Shopify, Next.js, etc.), CDN, analytics, and returns the page title, final URL after redirects, and key response headers. Use for competitive research and lead enrichment.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain or full URL, e.g. shopify.com" } },
      required: ["domain"],
    },
  },
  {
    name: "subdomains",
    description:
      "Discover subdomains of a domain from public Certificate Transparency logs (crt.sh). Useful for mapping a company's public surface (app., api., staging., etc.). Best-effort: crt.sh can be slow; returns a note if unavailable.",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Registrable domain, e.g. stripe.com" } },
      required: ["domain"],
    },
  },
];

class UserError extends Error {}

const FREE_PROVIDERS = new Set([
  "gmail.com","googlemail.com","yahoo.com","ymail.com","outlook.com","hotmail.com","live.com","msn.com",
  "aol.com","icloud.com","me.com","mac.com","proton.me","protonmail.com","gmx.com","gmx.net","mail.com",
  "zoho.com","yandex.com","yandex.ru","fastmail.com","tutanota.com","hey.com",
]);
const DISPOSABLE_PROVIDERS = new Set([
  "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com","temp-mail.org","throwawaymail.com",
  "yopmail.com","getnada.com","trashmail.com","sharklasers.com","dispostable.com","maildrop.cc","fakeinbox.com",
  "mohmal.com","emailondeck.com","mintemail.com","spamgourmet.com","tempr.email","moakt.com",
]);

function cleanDomain(input) {
  let d = String(input || "").trim().toLowerCase();
  if (d.includes("@")) d = d.split("@").pop();
  d = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:.*$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) throw new UserError("Invalid domain: " + input);
  return d;
}

async function doh(name, type) {
  const url = "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type;
  const res = await fetch(url, { cf: { cacheTtl: 900, cacheEverything: true }, headers: { accept: "application/dns-json" } });
  if (!res.ok) throw new UserError("DNS query failed (HTTP " + res.status + ")");
  const data = await res.json();
  return (data.Answer || []).map(function (a) { return a.data; });
}

async function domainIntel(args) {
  const domain = cleanDomain(args.domain);
  const res = await fetch("https://rdap.org/domain/" + encodeURIComponent(domain), { cf: { cacheTtl: 86400, cacheEverything: true },
    headers: { Accept: "application/rdap+json", "User-Agent": "datakoot-domain-intel-mcp" },
    redirect: "follow",
  });
  if (res.status === 404) return { domain: domain, found: false, note: "No RDAP record found. Domain may be unregistered or use a TLD without RDAP." };
  if (!res.ok) throw new UserError("RDAP lookup failed (HTTP " + res.status + ")");
  const d = await res.json();
  const events = {};
  for (const e of d.events || []) events[e.eventAction] = e.eventDate;
  let registrar = null, abuse = null;
  for (const ent of d.entities || []) {
    if ((ent.roles || []).indexOf("registrar") !== -1) {
      const fn = (ent.vcardArray && ent.vcardArray[1] || []).find(function (x) { return x[0] === "fn"; });
      if (fn) registrar = fn[3];
      for (const sub of ent.entities || []) {
        if ((sub.roles || []).indexOf("abuse") !== -1) {
          const em = (sub.vcardArray && sub.vcardArray[1] || []).find(function (x) { return x[0] === "email"; });
          if (em) abuse = em[3];
        }
      }
    }
  }
  const created = events.registration;
  let ageYears = null;
  if (created) ageYears = Math.floor((Date.now() - new Date(created).getTime()) / (365.25 * 24 * 3600 * 1000));
  return {
    domain: domain,
    found: true,
    registrar: registrar,
    created: created || null,
    expires: events.expiration || null,
    last_changed: events["last changed"] || null,
    age_years: ageYears,
    status: d.status || [],
    nameservers: (d.nameservers || []).map(function (n) { return (n.ldhName || "").toLowerCase(); }),
    dnssec_signed: Boolean(d.secureDNS && d.secureDNS.delegationSigned),
    abuse_contact: abuse,
  };
}

async function dnsLookup(args) {
  const domain = cleanDomain(args.domain);
  const all = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
  const types = Array.isArray(args.types) && args.types.length
    ? args.types.map(function (t) { return String(t).toUpperCase(); }).filter(function (t) { return all.indexOf(t) !== -1; })
    : all;
  const out = {};
  const failed = [];
  await Promise.all(types.map(async function (t) {
    // A failed lookup used to become [], which is indistinguishable from "this
    // domain genuinely has no records of this type". For anyone checking SPF or
    // DMARC that difference is the whole answer, so a failure is now null and
    // named explicitly.
    try { out[t] = await doh(domain, t); } catch (e) { out[t] = null; failed.push(t); }
  }));
  const result = { domain: domain, records: out };
  if (failed.length) {
    result.lookup_failed = failed;
    result.note = "DNS resolution failed for " + failed.join(", ") + ". Those types are null rather than empty: no answer was received, which is NOT evidence that no such record exists.";
  }
  return result;
}

async function emailDeliverability(args) {
  const domain = cleanDomain(args.domain_or_email);
  // Each of these used to fall back to [] on failure, which made a DNS outage
  // look like "no MX, no SPF, no DMARC" — i.e. the tool would confidently report
  // a domain as unable to receive mail and unprotected when it had simply failed
  // to look. Track what actually failed and refuse to assert absence for it.
  const dnsFailed = [];
  const safeDoh = function (n, t, label) {
    return doh(n, t).catch(function () { dnsFailed.push(label); return null; });
  };
  const [mxR, txtR, dmarcR] = await Promise.all([
    safeDoh(domain, "MX", "MX"),
    safeDoh(domain, "TXT", "TXT"),
    safeDoh("_dmarc." + domain, "TXT", "_dmarc TXT"),
  ]);
  const mx = mxR || [], txt = txtR || [], dmarcTxt = dmarcR || [];
  const spf = txt.map(function (t) { return t.replace(/"/g, ""); }).find(function (t) { return t.toLowerCase().indexOf("v=spf1") === 0; }) || null;
  const dmarc = dmarcTxt.map(function (t) { return t.replace(/"/g, ""); }).find(function (t) { return t.toLowerCase().indexOf("v=dmarc1") === 0; }) || null;
  let dmarcPolicy = null;
  if (dmarc) { const m = dmarc.match(/p=([a-z]+)/i); dmarcPolicy = m ? m[1].toLowerCase() : null; }
  const isFree = FREE_PROVIDERS.has(domain);
  const isDisposable = DISPOSABLE_PROVIDERS.has(domain);
  const mxUnknown = mxR === null;
  const hasMx = mx.length > 0;
  let verdict;
  if (mxUnknown) verdict = "unknown_dns_lookup_failed";
  else if (isDisposable) verdict = "disposable";
  else if (!hasMx) verdict = "cannot_receive_mail";
  else if (isFree) verdict = "free_consumer_provider";
  else verdict = "business_domain";
  return {
    domain: domain,
    can_receive_mail: mxUnknown ? null : hasMx,
    mx_hosts: mx.map(function (r) { return r.split(" ").pop(); }),
    spf: txtR === null ? null : spf,
    spf_checked: txtR !== null,
    dmarc_policy: dmarcR === null ? null : dmarcPolicy,
    dmarc_record: dmarcR === null ? null : dmarc,
    dmarc_checked: dmarcR !== null,
    is_free_provider: isFree,
    is_disposable: isDisposable,
    auth_posture: (txtR === null || dmarcR === null || mxUnknown)
      ? "unknown"
      : (hasMx ? ((spf ? 1 : 0) + (dmarc ? 1 : 0) === 2 ? "strong" : (spf || dmarc) ? "partial" : "none") : "n/a"),
    verdict: verdict,
    dns_lookup_failed: dnsFailed.length ? dnsFailed : undefined,
    note: dnsFailed.length
      ? "DNS lookup failed for: " + dnsFailed.join(", ") + ". The corresponding fields are null, not false. A failed lookup is not evidence that the record is missing, and this result must not be read as a finding about the domain's email security."
      : undefined,
  };
}

const TECH_SIGNATURES = [
  { name: "WordPress", test: function (h, b) { return /wp-content|wp-includes/i.test(b) || /wordpress/i.test(h.generator || ""); } },
  { name: "Shopify", test: function (h, b) { return /cdn\.shopify\.com|x-shopid/i.test(b + JSON.stringify(h)); } },
  { name: "Wix", test: function (h, b) { return /static\.wixstatic\.com|X-Wix/i.test(b + JSON.stringify(h)); } },
  { name: "Squarespace", test: function (h, b) { return /squarespace/i.test(b) || /Squarespace/i.test(h.server || ""); } },
  { name: "Webflow", test: function (h, b) { return /webflow/i.test(b) || /Webflow/i.test(h.generator || ""); } },
  { name: "Next.js", test: function (h, b) { return /_next\/static|__NEXT_DATA__/i.test(b) || "x-nextjs-cache" in h; } },
  { name: "Nuxt", test: function (h, b) { return /__NUXT__|_nuxt\//i.test(b); } },
  { name: "React", test: function (h, b) { return /data-reactroot|react\./i.test(b); } },
  { name: "Vue", test: function (h, b) { return /data-v-|vue(\.min)?\.js/i.test(b); } },
  { name: "Gatsby", test: function (h, b) { return /gatsby/i.test(b); } },
  { name: "HubSpot", test: function (h, b) { return /hs-scripts|hubspot/i.test(b); } },
  { name: "Drupal", test: function (h, b) { return /Drupal/i.test(b) || "x-drupal-cache" in h; } },
  { name: "Ghost", test: function (h, b) { return /ghost/i.test(h.generator || "") || /content=\"Ghost/i.test(b); } },
];
const ANALYTICS_SIGNATURES = [
  { name: "Google Analytics", re: /google-analytics\.com|gtag\(|googletagmanager\.com/i },
  { name: "Plausible", re: /plausible\.io/i },
  { name: "Segment", re: /cdn\.segment\.com/i },
  { name: "Mixpanel", re: /mixpanel/i },
  { name: "Hotjar", re: /hotjar/i },
  { name: "Meta Pixel", re: /connect\.facebook\.net|fbq\(/i },
];

function isBlockedHost(h){ h=(h||"").toLowerCase(); if(h===""||h==="localhost"||h.endsWith(".localhost")||h.endsWith(".internal")||h.endsWith(".local")) return true; const m=h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/); if(m){const a=+m[1],b=+m[2]; if(a===0||a===10||a===127) return true; if(a===169&&b===254) return true; if(a===172&&b>=16&&b<=31) return true; if(a===192&&b===168) return true; if(a>=224) return true;} if(h.includes(":")){ if(h==="::1"||h==="::"||h.startsWith("fc")||h.startsWith("fd")||h.startsWith("fe80")) return true; } return false; }
async function techStack(args) {
  let target = String(args.domain || "").trim();
  if (!/^https?:\/\//i.test(target)) target = "https://" + cleanDomain(target);
  let _u; try { _u = new URL(target); } catch (e) { throw new UserError("Invalid URL."); }
  if (!/^https?:$/.test(_u.protocol)) throw new UserError("Only http and https URLs are allowed.");
  if (isBlockedHost(_u.hostname)) throw new UserError("Refusing to fetch a private or internal host.");
  const controller = new AbortController();
  const timer = setTimeout(function () { controller.abort(); }, 8000);
  let res;
  try {
    res = await fetch(target, { cf: { cacheTtl: 3600, cacheEverything: true }, redirect: "follow", signal: controller.signal, headers: { "User-Agent": "Mozilla/5.0 (compatible; datakoot-domain-intel/1.0)" } });
  } catch (e) {
    clearTimeout(timer);
    throw new UserError("Could not fetch site: " + (e.name === "AbortError" ? "timed out" : e.message));
  }
  clearTimeout(timer);
  const headers = {};
  res.headers.forEach(function (v, k) { headers[k.toLowerCase()] = v; });
  let body = "";
  try { body = (await res.text()).slice(0, 200000); } catch (e) {}
  const genMatch = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  const generator = genMatch ? genMatch[1] : null;
  const titleMatch = body.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
  const hdrForSig = Object.assign({ generator: generator }, headers);
  const tech = TECH_SIGNATURES.filter(function (s) { return s.test(hdrForSig, body); }).map(function (s) { return s.name; });
  const analytics = ANALYTICS_SIGNATURES.filter(function (s) { return s.re.test(body); }).map(function (s) { return s.name; });
  return {
    url: res.url,
    status: res.status,
    title: titleMatch ? titleMatch[1].trim() : null,
    server: headers["server"] || null,
    powered_by: headers["x-powered-by"] || null,
    cdn: headers["cf-ray"] ? "Cloudflare" : (headers["x-served-by"] ? "Fastly" : (headers["x-amz-cf-id"] ? "CloudFront" : null)),
    generator: generator,
    technologies: tech,
    analytics: analytics,
    security_headers: {
      hsts: Boolean(headers["strict-transport-security"]),
      csp: Boolean(headers["content-security-policy"]),
      x_frame_options: headers["x-frame-options"] || null,
    },
  };
}

async function subdomains(args) {
  const domain = cleanDomain(args.domain);
  const controller = new AbortController();
  const timer = setTimeout(function () { controller.abort(); }, 9000);
  let res;
  try {
    res = await fetch("https://crt.sh/?q=%25." + encodeURIComponent(domain) + "&output=json", { cf: { cacheTtl: 86400, cacheEverything: true }, signal: controller.signal, headers: { "User-Agent": "datakoot-domain-intel-mcp" } });
  } catch (e) {
    clearTimeout(timer);
    return { domain: domain, available: false, note: "Certificate Transparency source (crt.sh) unavailable or timed out. Try again shortly." };
  }
  clearTimeout(timer);
  if (!res.ok) return { domain: domain, available: false, note: "crt.sh returned HTTP " + res.status };
  let rows;
  try { rows = await res.json(); } catch (e) { return { domain: domain, available: false, note: "crt.sh returned no parseable data." }; }
  const set = new Set();
  for (const r of rows || []) {
    String(r.name_value || "").split("\n").forEach(function (n) {
      n = n.trim().toLowerCase();
      if (n && !n.startsWith("*.") && (n === domain || n.endsWith("." + domain))) set.add(n);
    });
  }
  const list = Array.from(set).sort();
  return { domain: domain, available: true, count: list.length, subdomains: list.slice(0, 200), truncated: list.length > 200 };
}

async function domainReport(args) {
  const domain = cleanDomain(args.domain);
  const settle = function (p) { return p.then(function (v) { return v; }, function (e) { return { error: e.message }; }); };
  const parts = await Promise.all([ settle(domainIntel({ domain: domain })), settle(dnsLookup({ domain: domain })), settle(emailDeliverability({ domain_or_email: domain })), settle(techStack({ domain: domain })) ]);
  return { domain: domain, registration: parts[0], dns: (parts[1] && parts[1].records) ? parts[1].records : parts[1], email: parts[2], tech: parts[3] };
}

const TOOL_IMPLS = {
  domain_report: domainReport,
  domain_intel: domainIntel,
  dns_lookup: dnsLookup,
  email_deliverability: emailDeliverability,
  tech_stack: techStack,
  subdomains: subdomains,
};

function rpcResult(id, result) { return { jsonrpc: "2.0", id: id, result: result }; }
function rpcError(id, code, message) { return { jsonrpc: "2.0", id: id, error: { code: code, message: message } }; }

async function handleRpc(msg, env, tier) {
  const id = msg.id, method = msg.method, params = msg.params;
  console.log("DKPULSE " + (method || "?") + " " + ((params && params.name) || "-"));
  if (id === undefined || id === null) return null;
  switch (method) {
    case "initialize": {
      const requested = params && params.protocolVersion;
      return rpcResult(id, {
        protocolVersion: PROTOCOL_VERSIONS.indexOf(requested) !== -1 ? requested : PROTOCOL_VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions: "Domain and company intelligence tools for AI agents: registration data (RDAP), DNS records, email deliverability, website tech-stack fingerprinting, and subdomain discovery. Use for lead qualification, competitive research, and reconnaissance.",
      });
    }
    case "ping": return rpcResult(id, {});
    case "tools/list": return rpcResult(id, { tools: TOOLS });
    case "tools/call": {
      const name = params && params.name;
      const impl = TOOL_IMPLS[name];
      if (!impl) return rpcError(id, -32602, "Unknown tool: " + name); { const _d = TOOLS.find((t) => t.name === name); const _s = ((_d && _d.inputSchema) || {}).properties || {}; const _a = (params && params.arguments) || {}; const _rq = ((_d && _d.inputSchema) || {}).required || []; const _bad = Object.keys(_a).filter((k) => !(k in _s)).map((k) => "unexpected '" + k + "'").concat(_rq.filter((k) => _a[k] === undefined || _a[k] === null || _a[k] === "").map((k) => "missing required '" + k + "'")); if (_bad.length) return rpcError(id, -32602, "Bad arguments for " + name + ": " + _bad.join(", ") + ". Valid: " + (Object.keys(_s).join(", ") || "none") + ". The call was refused rather than ignoring them, because ignoring an argument returns a confident answer to a different question than the one asked."); }
      try { console.log(JSON.stringify({ datakoot_metric: "tool_call", tool: String(name), tier: String(tier || "free"), ts: Date.now() })); } catch (e) {}
      try {
        const out = await impl((params && params.arguments) || {}, env);
        return rpcResult(id, { content: [{ type: "text", text: JSON.stringify(tier === "pro" ? out : dkCapNote(out), null, 2) }] });
      } catch (e) {
        const message = e instanceof UserError ? e.message : "Internal error: " + e.message;
        return rpcResult(id, { content: [{ type: "text", text: message }], isError: true });
      }
    }
    case "resources/list": return rpcResult(id, { resources: [] });
    case "prompts/list": return rpcResult(id, { prompts: [] });
    default: return rpcError(id, -32601, "Method not found: " + method);
  }
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version",
  "Access-Control-Expose-Headers": "Mcp-Session-Id",
};


const POLAR_ORG_ID = "7f455043-0b15-4a1c-b7a0-9c06c9f3b95e";
const UPGRADE_URL = "https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf";
async function validatePolarKey(key){ if(!key) return {tier:"free"}; if(!/^[A-Za-z0-9][A-Za-z0-9-]{5,120}$/.test(key)) return {tier:"free",key_status:"malformed"}; const cache=caches.default; const ck=new Request("https://polar-validate.datakoot.internal/"+encodeURIComponent(key)); const hit=await cache.match(ck); if(hit){try{return await hit.json();}catch(e){}} let result={tier:"free",key_status:"invalid"}; try{ const r=await fetch("https://api.polar.sh/v1/customer-portal/license-keys/validate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:key,organization_id:POLAR_ORG_ID})}); if(r.ok){const d=await r.json(); const active=d.status==="granted"&&(!d.expires_at||new Date(d.expires_at).getTime()>Date.now()); result=active?{tier:"pro",key_status:"granted"}:{tier:"free",key_status:d.status||"inactive"};}}catch(e){} const store=new Response(JSON.stringify(result),{headers:{"Cache-Control":"s-maxage=300"}}); await cache.put(ck,store); return result; }
function dkCapNote(out) {
  let before = null;
  try { before = JSON.parse(JSON.stringify(out)); } catch (e) {}
  const capped = capForFree(out);
  try {
    const shrunk = [];
    const walk = (a, b, path) => {
      if (!a || !b || typeof a !== "object" || typeof b !== "object") return;
      for (const k of Object.keys(a)) {
        const av = a[k], bv = b[k];
        const p = path ? path + "." + k : k;
        if (Array.isArray(av) && Array.isArray(bv) && bv.length < av.length) shrunk.push(p + " (" + bv.length + " of " + av.length + ")");
        else if (av && typeof av === "object" && bv && typeof bv === "object") walk(av, bv, p);
      }
    };
    if (before) walk(before, capped, "");
    if (shrunk.length && capped && typeof capped === "object") capped.free_tier_note = "Shortened for the free tier: list results are capped at 10 items per call — " + shrunk.join(", ") + ". The counts in this response are the true totals, not the number of items returned. A Datakoot Pro key removes the cap.";
  } catch (e) {}
  return capped;
}
function capForFree(out){ try{ const o=JSON.parse(JSON.stringify(out)); let t=false; const walk=(v)=>{if(Array.isArray(v)){if(v.length>10){t=true;v.length=10;}v.forEach(walk);}else if(v&&typeof v==="object"){for(const k in v)walk(v[k]);}}; walk(o); if(t&&o&&typeof o==="object"&&!Array.isArray(o))o._datakoot_note="Free tier: results capped at 10 items. Upgrade for full results at https://datakoot.com"; return o;}catch(e){return out;} }


const LANDING_HTML = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Domain & Company Intel MCP — Vet any domain from your AI agent | Datakoot</title><link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\"><meta property=\"og:type\" content=\"website\"><meta property=\"og:site_name\" content=\"Datakoot\"><meta property=\"og:title\" content=\"Domain & Company Intel MCP — Datakoot\"><meta property=\"og:description\" content=\"Vet any domain from your AI agent: RDAP registration, DNS, email deliverability, tech-stack detection, subdomains.\"><meta property=\"og:image\" content=\"https://domain.datakoot.com/og.png\"><meta property=\"og:url\" content=\"https://domain.datakoot.com/\"><meta name=\"twitter:card\" content=\"summary_large_image\"><meta name=\"twitter:title\" content=\"Domain & Company Intel MCP — Datakoot\"><meta name=\"twitter:description\" content=\"Know who is behind any domain.\"><meta name=\"twitter:image\" content=\"https://domain.datakoot.com/og.png\"><meta name=\"description\" content=\"Domain and company intelligence tools for AI agents: registration data, DNS, email deliverability, tech-stack detection, subdomain discovery. One MCP endpoint, no API keys.\"><style>:root{--bg:#0b0e14;--panel:#131722;--border:#232936;--text:#e6e9ef;--muted:#9aa3b2;--accent:#4ade80;--accent2:#22d3ee}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,sans-serif;line-height:1.6}.wrap{max-width:960px;margin:0 auto;padding:0 24px}header{padding:28px 0;display:flex;justify-content:space-between;align-items:center}.logo{font-weight:800;font-size:1.15rem}.logo span{color:var(--accent)}nav a{color:var(--muted);text-decoration:none;margin-left:22px;font-size:.95rem}nav a:hover{color:var(--text)}@media(max-width:600px){header{flex-direction:column;align-items:flex-start;gap:12px;padding:18px 0}nav{display:flex;flex-wrap:wrap;gap:6px 18px}nav a{margin-left:0}}.hero{padding:72px 0 48px;text-align:center}.hero h1{font-size:clamp(2rem,5vw,3.2rem);line-height:1.15;font-weight:800}.hero h1 em{font-style:normal;color:var(--accent)}.hero p.sub{color:var(--muted);font-size:1.15rem;max-width:640px;margin:20px auto 0}.badges{margin-top:18px;color:var(--muted);font-size:.9rem}.cta{margin-top:32px;display:flex;gap:14px;justify-content:center;flex-wrap:wrap}.btn{padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:600;font-size:.98rem}.btn.primary{background:var(--accent);color:#06220f}.btn.ghost{border:1px solid var(--border);color:var(--text)}.section{padding:48px 0;border-top:1px solid var(--border)}.section h2{font-size:1.5rem;margin-bottom:8px}.section p.lead{color:var(--muted);margin-bottom:28px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px}.card h3{font-size:1rem;margin-bottom:6px}.card h3 code{color:var(--accent2);font-size:.95rem}.card p{color:var(--muted);font-size:.9rem}.card .src{margin-top:10px;font-size:.78rem;color:var(--muted);opacity:.8}pre{background:#0a0d13;border:1px solid var(--border);border-radius:10px;padding:16px;overflow-x:auto;font-size:.85rem;line-height:1.5}pre code{color:#c8d3e8;font-family:ui-monospace,Menlo,Consolas,monospace}.steps h3{margin:26px 0 10px;font-size:1.02rem}.pricing .card.featured{border-color:var(--accent)}.pricing .price{font-size:1.7rem;font-weight:800;margin:8px 0}.pricing .price small{font-size:.85rem;color:var(--muted);font-weight:400}.pricing ul{list-style:none;margin-top:10px}.pricing li{color:var(--muted);font-size:.9rem;padding:3px 0}.pricing li:before{content:\"✓ \";color:var(--accent)}.note{background:var(--panel);border:1px solid var(--accent);border-radius:10px;padding:14px 18px;margin-top:22px;font-size:.92rem;color:var(--muted)}.note strong{color:var(--accent)}footer{border-top:1px solid var(--border);padding:36px 0;color:var(--muted);font-size:.88rem;text-align:center}footer a{color:var(--muted)}</style></head><body><div class=\"wrap\"><header style=\"position:sticky;top:0;z-index:50;background:#0b0e14;border-bottom:1px solid #1a2230\"><a href=\"https://datakoot.com/\" style=\"text-decoration:none;color:inherit\"><div class=\"logo\"><svg width=\"20\" height=\"20\" viewBox=\"-34 -34 68 68\" style=\"vertical-align:-3px;margin-right:7px\"><g stroke=\"#4ade80\" stroke-width=\"5\" fill=\"none\" stroke-linejoin=\"round\"><polygon points=\"0,-30 26,-15 26,15 0,30 -26,15 -26,-15\"/></g><g fill=\"#4ade80\"><circle cx=\"0\" cy=\"-12\" r=\"6\"/><circle cx=\"-11\" cy=\"8\" r=\"6\"/><circle cx=\"11\" cy=\"8\" r=\"6\"/></g></svg>Data<span>koot</span></div></a><nav><a href=\"https://datakoot.com/\">Datakoot</a><a href=\"#tools\">Tools</a><a href=\"#start\">Quick start</a><a href=\"#pricing\">Pricing</a><a href=\"https://github.com/datakoot/domain-intel-mcp\">GitHub</a></nav></header><section class=\"hero\"><h1>Know who is behind<br><em>any domain</em></h1><p class=\"sub\">Give your AI agent domain and company intelligence: vet a lead, research a competitor, or map a target — all from free public data, no API keys.</p><div class=\"badges\">Listed in the Official MCP Registry · Open source (MIT) · No install required</div><div class=\"cta\"><a class=\"btn primary\" href=\"#start\">Add to your agent →</a><a class=\"btn ghost\" href=\"https://github.com/datakoot/domain-intel-mcp\">View source</a></div></section><section class=\"section\" id=\"tools\"><h2>Six checks, one endpoint</h2><p class=\"lead\">Everything an agent needs to size up a domain or company.</p><div class=\"grid\"><div class=\"card\"><h3><code>domain_intel</code></h3><p>Registrar, creation/expiry dates, domain age, status, nameservers, DNSSEC — how established is this company?</p><div class=\"src\">Source: RDAP</div></div><div class=\"card\"><h3><code>dns_lookup</code></h3><p>A, AAAA, MX, NS, TXT, CNAME, SOA records — where a domain is hosted and who runs its mail.</p><div class=\"src\">Source: Cloudflare DoH</div></div><div class=\"card\"><h3><code>email_deliverability</code></h3><p>MX presence, SPF/DMARC posture, free vs. disposable provider, verdict — qualify leads, flag throwaways.</p><div class=\"src\">Source: DNS</div></div><div class=\"card\"><h3><code>tech_stack</code></h3><p>Web server, CMS/framework, CDN, analytics, security headers — what a site is built on.</p><div class=\"src\">Source: Live fetch</div></div><div class=\"card\"><h3><code>subdomains</code></h3><p>Subdomain discovery from Certificate Transparency logs — map a company public surface.</p><div class=\"src\">Source: crt.sh</div></div><div class=\"card\"><h3><code>domain_report</code></h3><p>One call returns a full dossier on a domain: registration, DNS, email deliverability, and website tech stack, combined.</p><div class=\"src\">Source: all-in-one</div></div></div></section><section class=\"section steps\" id=\"start\"><h2>Quick start</h2><p class=\"lead\">Hosted endpoint, nothing to install.</p><h3>Claude Code</h3><pre><code>claude mcp add --transport http domain-intel https://domain.datakoot.com/mcp</code></pre><h3>Then try</h3><pre><code>\"Is acme.com a real, established business?\"\n\"This lead is @acme.io — can it receive mail, is it a throwaway?\"\n\"What is competitor.com built on?\"</code></pre></section><section class=\"section pricing\" id=\"pricing\"><h2>Pricing</h2><p class=\"lead\">Every server has a free tier: 100 calls a day. Upgrade to Pro for more calls a month.</p><div class=\"grid\"><div class=\"card featured\"><h3>Free</h3><div class=\"price\">$0<small>/mo</small></div><ul><li>All six tools</li><li>100 tool calls/day</li><li>Hosted endpoint</li><li>Community support</li></ul></div><div class=\"card\"><h3>Pro</h3><div class=\"price\">$15<small>/mo</small></div><ul><li>50,000 calls / month · no daily limit</li><li>One key, all nine servers</li><li>Priority endpoint</li><li>Email support</li><a class=\"btn primary\" href=\"https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf\" style=\"display:inline-block;margin-top:14px\">Subscribe →</a></ul></div></div><div class=\"note\"><strong>One key, every server.</strong> A Datakoot subscription unlocks Pro across every Datakoot server, including the <a href=\"https://security.datakoot.com\" style=\"color:var(--accent2)\">Security Intel</a> server. Self-host free on Cloudflare — <a href=\"https://github.com/datakoot/domain-intel-mcp\" style=\"color:var(--accent2)\">GitHub</a>.</div></section><footer><a href=\"https://datakoot.com/\" style=\"color:inherit\">Datakoot</a> — infrastructure for the agent economy · <a href=\"https://github.com/datakoot\">GitHub</a> · Data: RDAP, Cloudflare DNS, crt.sh</footer></div></body></html>";
const PAGES = { "/guides/domain-dossier": "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Get a Full Domain Dossier for Lead Qualification | Datakoot</title><meta name=\"description\" content=\"Turn a domain into a full company dossier in one call from your AI agent: registration, DNS, email deliverability, and tech stack. Via an MCP server.\"><style>:root{--bg:#0b0e14;--panel:#131722;--border:#232936;--text:#e6e9ef;--muted:#9aa3b2;--accent:#4ade80;--accent2:#22d3ee}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,sans-serif;line-height:1.7}.wrap{max-width:760px;margin:0 auto;padding:24px}a{color:var(--accent2)}h1{font-size:1.9rem;line-height:1.2;margin:24px 0 8px}h2{font-size:1.25rem;margin:32px 0 8px}p{margin:12px 0}.muted{color:var(--muted)}pre{background:#0a0d13;border:1px solid var(--border);border-radius:10px;padding:14px;overflow-x:auto;font-size:.85rem;margin:14px 0}code{font-family:ui-monospace,Menlo,Consolas,monospace}.top{padding:16px 0;border-bottom:1px solid var(--border)}.top a{color:var(--text);text-decoration:none;font-weight:800}.top span{color:var(--accent)}footer{margin-top:48px;padding:20px 0;border-top:1px solid var(--border);font-size:.85rem;color:var(--muted)}</style></head><body><div class=\"wrap\"><div class=\"top\"><a href=\"/\">Data<span>koot</span></a></div><section><h1>Get a Full Domain Dossier in One Call (for Lead Qualification)</h1><p class=\"muted\">Updated July 2026</p><p>When a lead or prospect comes in as just a domain, an AI agent can size up the whole company in seconds. The <code>domain_report</code> tool returns a complete dossier in a single call instead of four separate lookups.</p><h2>What is in the dossier</h2><p>One call to <code>domain_report</code> combines: <strong>registration</strong> (registrar, domain age, expiry via RDAP), <strong>DNS</strong> (A/MX/NS/TXT records), <strong>email deliverability</strong> (MX presence, SPF/DMARC, free vs. disposable provider), and <strong>tech stack</strong> (web server, CMS/framework, CDN). Everything an SDR would check to judge whether a lead is a real, established business worth pursuing.</p><h2>Setup</h2><pre><code>claude mcp add --transport http domain-intel https://domain.datakoot.com/mcp</code></pre><p>No API key needed. Then:</p><pre><code>\"Give me a full dossier on acme.com — is it an established business, and what are they running?\"</code></pre><h2>Why one call matters</h2><p>For an agent qualifying a list of leads, one round-trip per domain instead of four means faster, cheaper enrichment. Free tier caps results; a Pro key returns the full report. Open source (MIT) — see <a href=\"https://github.com/datakoot/domain-intel-mcp\">GitHub</a> or the <a href=\"/#pricing\">pricing</a>.</p></section><footer><a href=\"https://datakoot.com/\" style=\"color:inherit\">Datakoot</a> · <a href=\"/\">Home</a> · <a href=\"https://github.com/datakoot/domain-intel-mcp\">GitHub</a></footer></div></body></html>", "/guides/lead-qualification-mcp": "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Qualify Leads from a Domain with AI Agents | Datakoot</title><meta name=\"description\" content=\"Turn a lead email or company domain into a qualification signal: is it a real business, can it receive mail, is it a disposable address? Via one MCP server.\"><style>:root{--bg:#0b0e14;--panel:#131722;--border:#232936;--text:#e6e9ef;--muted:#9aa3b2;--accent:#4ade80;--accent2:#22d3ee}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,sans-serif;line-height:1.6}.wrap{max-width:960px;margin:0 auto;padding:0 24px}header{padding:28px 0;display:flex;justify-content:space-between;align-items:center}.logo{font-weight:800;font-size:1.15rem}.logo span{color:var(--accent)}nav a{color:var(--muted);text-decoration:none;margin-left:22px;font-size:.95rem}nav a:hover{color:var(--text)}@media(max-width:600px){header{flex-direction:column;align-items:flex-start;gap:12px;padding:18px 0}nav{display:flex;flex-wrap:wrap;gap:6px 18px}nav a{margin-left:0}}.hero{padding:72px 0 48px;text-align:center}.hero h1{font-size:clamp(2rem,5vw,3.2rem);line-height:1.15;font-weight:800}.hero h1 em{font-style:normal;color:var(--accent)}.hero p.sub{color:var(--muted);font-size:1.15rem;max-width:640px;margin:20px auto 0}.badges{margin-top:18px;color:var(--muted);font-size:.9rem}.cta{margin-top:32px;display:flex;gap:14px;justify-content:center;flex-wrap:wrap}.btn{padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:600;font-size:.98rem}.btn.primary{background:var(--accent);color:#06220f}.btn.ghost{border:1px solid var(--border);color:var(--text)}.section{padding:48px 0;border-top:1px solid var(--border)}.section h2{font-size:1.5rem;margin-bottom:8px}.section p.lead{color:var(--muted);margin-bottom:28px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px}.card h3{font-size:1rem;margin-bottom:6px}.card h3 code{color:var(--accent2);font-size:.95rem}.card p{color:var(--muted);font-size:.9rem}.card .src{margin-top:10px;font-size:.78rem;color:var(--muted);opacity:.8}pre{background:#0a0d13;border:1px solid var(--border);border-radius:10px;padding:16px;overflow-x:auto;font-size:.85rem;line-height:1.5}pre code{color:#c8d3e8;font-family:ui-monospace,Menlo,Consolas,monospace}.steps h3{margin:26px 0 10px;font-size:1.02rem}.pricing .card.featured{border-color:var(--accent)}.pricing .price{font-size:1.7rem;font-weight:800;margin:8px 0}.pricing .price small{font-size:.85rem;color:var(--muted);font-weight:400}.pricing ul{list-style:none;margin-top:10px}.pricing li{color:var(--muted);font-size:.9rem;padding:3px 0}.pricing li:before{content:\"✓ \";color:var(--accent)}.note{background:var(--panel);border:1px solid var(--accent);border-radius:10px;padding:14px 18px;margin-top:22px;font-size:.92rem;color:var(--muted)}.note strong{color:var(--accent)}footer{border-top:1px solid var(--border);padding:36px 0;color:var(--muted);font-size:.88rem;text-align:center}footer a{color:var(--muted)}</style></head><body><div class=\"wrap\"><header style=\"position:sticky;top:0;z-index:50;background:#0b0e14;border-bottom:1px solid #1a2230\"><a href=\"https://datakoot.com/\" style=\"text-decoration:none;color:inherit\"><div class=\"logo\">Data<span>koot</span></div></a><nav><a href=\"/\">Home</a><a href=\"/#pricing\">Pricing</a></nav></header><section class=\"section\"><h1>Qualify Leads from a Domain with AI Agents</h1><p class=\"lead\">Updated July 2026</p><p>When a lead comes in with just an email or a company URL, an AI agent can size it up in seconds instead of guessing. Domain & Company Intel MCP gives your agent the checks a careful SDR would run.</p><h2>The signals that matter</h2><p><strong>Is the company real and established?</strong> <code>domain_intel</code> returns the domain age, registrar, and registration dates from RDAP. A domain registered last week behaves very differently from one registered in 2009.</p><p><strong>Can the email even receive mail, and is it a throwaway?</strong> <code>email_deliverability</code> checks for MX records, reads SPF/DMARC posture, and flags free consumer providers (gmail) and known disposable/temp-mail domains — so your agent can down-rank throwaway signups automatically.</p><p><strong>What is the company running?</strong> <code>tech_stack</code> fingerprints their website (Shopify, WordPress, Next.js, etc.), which is a strong fit signal for many B2B products.</p><h2>Setup</h2><pre><code>claude mcp add --transport http domain-intel https://domain.datakoot.com/mcp</code></pre><p>No API keys required. Free tier is fully functional; upgrade for unlimited results at <a href=\"/#pricing\" style=\"color:var(--accent2)\">Datakoot pricing</a>.</p></section><footer><a href=\"https://datakoot.com/\" style=\"color:inherit\">Datakoot</a> · <a href=\"/\">Home</a> · <a href=\"https://github.com/datakoot/domain-intel-mcp\">GitHub</a></footer></div></body></html>", "/guides/email-deliverability-check": "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Check Email Deliverability and Disposable Domains | Datakoot</title><meta name=\"description\" content=\"Detect whether an email domain can receive mail and whether it is a disposable/temp-mail provider, from your AI agent via MCP.\"><style>:root{--bg:#0b0e14;--panel:#131722;--border:#232936;--text:#e6e9ef;--muted:#9aa3b2;--accent:#4ade80;--accent2:#22d3ee}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,sans-serif;line-height:1.6}.wrap{max-width:960px;margin:0 auto;padding:0 24px}header{padding:28px 0;display:flex;justify-content:space-between;align-items:center}.logo{font-weight:800;font-size:1.15rem}.logo span{color:var(--accent)}nav a{color:var(--muted);text-decoration:none;margin-left:22px;font-size:.95rem}nav a:hover{color:var(--text)}@media(max-width:600px){header{flex-direction:column;align-items:flex-start;gap:12px;padding:18px 0}nav{display:flex;flex-wrap:wrap;gap:6px 18px}nav a{margin-left:0}}.hero{padding:72px 0 48px;text-align:center}.hero h1{font-size:clamp(2rem,5vw,3.2rem);line-height:1.15;font-weight:800}.hero h1 em{font-style:normal;color:var(--accent)}.hero p.sub{color:var(--muted);font-size:1.15rem;max-width:640px;margin:20px auto 0}.badges{margin-top:18px;color:var(--muted);font-size:.9rem}.cta{margin-top:32px;display:flex;gap:14px;justify-content:center;flex-wrap:wrap}.btn{padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:600;font-size:.98rem}.btn.primary{background:var(--accent);color:#06220f}.btn.ghost{border:1px solid var(--border);color:var(--text)}.section{padding:48px 0;border-top:1px solid var(--border)}.section h2{font-size:1.5rem;margin-bottom:8px}.section p.lead{color:var(--muted);margin-bottom:28px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px}.card h3{font-size:1rem;margin-bottom:6px}.card h3 code{color:var(--accent2);font-size:.95rem}.card p{color:var(--muted);font-size:.9rem}.card .src{margin-top:10px;font-size:.78rem;color:var(--muted);opacity:.8}pre{background:#0a0d13;border:1px solid var(--border);border-radius:10px;padding:16px;overflow-x:auto;font-size:.85rem;line-height:1.5}pre code{color:#c8d3e8;font-family:ui-monospace,Menlo,Consolas,monospace}.steps h3{margin:26px 0 10px;font-size:1.02rem}.pricing .card.featured{border-color:var(--accent)}.pricing .price{font-size:1.7rem;font-weight:800;margin:8px 0}.pricing .price small{font-size:.85rem;color:var(--muted);font-weight:400}.pricing ul{list-style:none;margin-top:10px}.pricing li{color:var(--muted);font-size:.9rem;padding:3px 0}.pricing li:before{content:\"✓ \";color:var(--accent)}.note{background:var(--panel);border:1px solid var(--accent);border-radius:10px;padding:14px 18px;margin-top:22px;font-size:.92rem;color:var(--muted)}.note strong{color:var(--accent)}footer{border-top:1px solid var(--border);padding:36px 0;color:var(--muted);font-size:.88rem;text-align:center}footer a{color:var(--muted)}</style></head><body><div class=\"wrap\"><header style=\"position:sticky;top:0;z-index:50;background:#0b0e14;border-bottom:1px solid #1a2230\"><a href=\"https://datakoot.com/\" style=\"text-decoration:none;color:inherit\"><div class=\"logo\">Data<span>koot</span></div></a><nav><a href=\"/\">Home</a><a href=\"/#pricing\">Pricing</a></nav></header><section class=\"section\"><h1>Check Email Deliverability & Disposable Domains</h1><p class=\"lead\">Updated July 2026</p><p>Fake and throwaway email signups pollute your funnel and skew your metrics. An AI agent can screen them at the point of entry with one call.</p><h2>What the check returns</h2><p><code>email_deliverability</code> takes a domain or an email address and returns: whether the domain has MX records (can it receive mail at all), its SPF and DMARC policy, whether it is a free consumer provider, whether it is a known disposable/temp-mail domain, and an overall verdict — business_domain, free_consumer_provider, disposable, or cannot_receive_mail.</p><h2>Example</h2><pre><code>\"Screen this signup email: test@mailinator.com\"</code></pre><p>returns verdict: disposable — your agent flags it instantly.</p><h2>Setup</h2><pre><code>claude mcp add --transport http domain-intel https://domain.datakoot.com/mcp</code></pre><p>Open source (MIT), self-hostable. <a href=\"https://github.com/datakoot/domain-intel-mcp\" style=\"color:var(--accent2)\">GitHub</a>.</p></section><footer><a href=\"https://datakoot.com/\" style=\"color:inherit\">Datakoot</a> · <a href=\"/\">Home</a> · <a href=\"https://github.com/datakoot/domain-intel-mcp\">GitHub</a></footer></div></body></html>" };
const ROBOTS_TXT = "User-agent: *\nAllow: /\nSitemap: https://domain.datakoot.com/sitemap.xml\n";
const SITEMAP_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n<url><loc>https://domain.datakoot.com/</loc></url>\n<url><loc>https://domain.datakoot.com/guides/lead-qualification-mcp</loc></url>\n<url><loc>https://domain.datakoot.com/guides/email-deliverability-check</loc></url>\n<url><loc>https://domain.datakoot.com/guides/domain-dossier</loc></url></urlset>\n";

const FAVICON_SVG="<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"-40 -40 80 80\"><rect x=\"-40\" y=\"-40\" width=\"80\" height=\"80\" rx=\"18\" fill=\"#0b0e14\"/><g stroke=\"#4ade80\" stroke-width=\"4\" fill=\"none\" stroke-linejoin=\"round\"><polygon points=\"0,-30 26,-15 26,15 0,30 -26,15 -26,-15\"/></g><g fill=\"#4ade80\"><circle cx=\"0\" cy=\"-12\" r=\"5\"/><circle cx=\"-11\" cy=\"8\" r=\"5\"/><circle cx=\"11\" cy=\"8\" r=\"5\"/></g><g stroke=\"#22d3ee\" stroke-width=\"2.5\"><line x1=\"0\" y1=\"-12\" x2=\"-11\" y2=\"8\"/><line x1=\"0\" y1=\"-12\" x2=\"11\" y2=\"8\"/><line x1=\"-11\" y1=\"8\" x2=\"11\" y2=\"8\"/></g></svg>";
const LLMS_TXT="# Datakoot Domain & Company Intel MCP\n\n> Domain and company intelligence for AI agents. Add this MCP server so your agent can vet a company, qualify a lead, or map a target from just a domain or email.\n\n## Add to your agent\nclaude mcp add --transport http domain-intel https://domain.datakoot.com/mcp\n\n## Tools\n- domain_intel: registrar, dates, age, status, nameservers via RDAP\n- dns_lookup: A/AAAA/MX/NS/TXT/CNAME/SOA records\n- email_deliverability: MX + SPF/DMARC, free vs disposable provider, verdict\n- tech_stack: web server, CMS/framework, CDN, analytics fingerprint\n- subdomains: certificate-transparency subdomain discovery\n- domain_report: one-call full dossier (all of the above combined)\n\n## Pricing\nFree tier: 100 calls a day, no key, no signup. Pro is $15/mo and includes 50,000 calls a month with no daily limit; one key unlocks all nine Datakoot servers.\nSubscribe: https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf\n\n## Source\nhttps://github.com/datakoot/domain-intel-mcp (MIT)\n";
/* checkAccess() was removed on 2026-09-02. It was defined but never called —
 * dkGate() is the live paywall — and it still held the old licence test
 * `d.status === "granted" || d.valid || d.id`, whose `|| d.id` clause accepts a
 * REVOKED key, because Polar returns the key object for revoked keys too.
 * Dead code that would silently reinstate a fixed billing hole if anyone ever
 * re-pointed a call site at it. */
export default {
  async fetch(request, env) { if (DK_SALT === null) DK_SALT = env.IP_SALT || ""; let _rlh = {}; try { if (request.method === "POST") { const _cl = request.clone(); const _bd = await _cl.json().catch(function(){return null;}); const _mm = _bd && (Array.isArray(_bd) ? _bd[0] : _bd); if (_mm && _mm.method === "tools/call") { const _g = await dkGate(request, env); _rlh = _g.headers || {}; if (!_g.allowed) { const _id = (_mm.id != null) ? _mm.id : null; return new Response(JSON.stringify({ jsonrpc: "2.0", id: _id, result: { content: [{ type: "text", text: _g.message }], isError: true } }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", ..._g.headers } }); } } } } catch (_e) {} 
    const url = new URL(request.url);
    if (url.pathname.endsWith("/.well-known/owners.json")) return new Response(JSON.stringify({ $schema: "https://verifymcp.io/schemas/owners.json", owners: ["hello@datakoot.com"] }), { headers: { "Content-Type": "application/json" } });
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === "/" && request.method === "GET") return new Response(LANDING_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    if (url.pathname === "/health" && request.method === "GET") {
      return new Response(JSON.stringify({
        service: SERVER_INFO.name, version: SERVER_INFO.version, mcp_endpoint: "/mcp",
        docs: "https://datakoot.com", tools: TOOLS.map(function (t) { return t.name; }),
      }, null, 2), { headers: Object.assign({ "Content-Type": "application/json" }, CORS) });
    }
    if (PAGES[url.pathname] && request.method === "GET") return new Response(PAGES[url.pathname], { headers: { "Content-Type": "text/html; charset=utf-8" } });
    if (url.pathname === "/robots.txt") return new Response(ROBOTS_TXT, { headers: { "Content-Type": "text/plain" } });
    if (url.pathname === "/sitemap.xml") return new Response(SITEMAP_XML, { headers: { "Content-Type": "application/xml" } });
    if (url.pathname === "/favicon.svg") return new Response(FAVICON_SVG, { headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" } });
    if (url.pathname === "/og.png") return Response.redirect("https://datakoot.com/og/domain-company.png", 301);
    if (url.pathname === "/llms.txt") return new Response(LLMS_TXT, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
    if (url.pathname !== "/mcp") return new Response("Not found", { status: 404, headers: CORS });
    if (env && env.SERVER_API_KEY) {
      const auth = request.headers.get("Authorization") || "";
      if (auth !== "Bearer " + env.SERVER_API_KEY)
        return new Response(JSON.stringify(rpcError(null, -32000, "Unauthorized: missing or invalid API key")), { status: 401, headers: Object.assign({ "Content-Type": "application/json" }, CORS) });
    }
    if (request.method === "GET") return new Response(null, { status: 405, headers: Object.assign({ Allow: "POST" }, CORS) });
    if (request.method === "DELETE") return new Response(null, { status: 200, headers: CORS });
    if (request.method !== "POST") return new Response(null, { status: 405, headers: Object.assign({ Allow: "POST" }, CORS) });
    let body;
    try { body = await request.json(); } catch (e) {
      return new Response(JSON.stringify(rpcError(null, -32700, "Parse error")), { status: 400, headers: Object.assign({ "Content-Type": "application/json" }, CORS) });
    }
    const _auth = request.headers.get("Authorization") || "";
    const _key = _auth.indexOf("Bearer ") === 0 ? _auth.slice(7).trim() : "";
    const _ti = await validatePolarKey(_key);
    const tier = _ti.tier;
    const messages = Array.isArray(body) ? body : [body];
    const settled = await Promise.all(messages.map(function (m) { return handleRpc(m, env, tier); }));
    const responses = settled.filter(function (r) { return r !== null; });
    if (responses.length === 0) return new Response(null, { status: 202, headers: CORS });
    const payload = Array.isArray(body) ? responses : responses[0];
    const th = { "Content-Type": "application/json", "X-Datakoot-Tier": tier, "X-Datakoot-Upgrade": tier === "pro" ? "" : UPGRADE_URL };
    return new Response(JSON.stringify(payload), { headers: Object.assign(th, CORS, _rlh) });
  },
};


/* ==================== Datakoot call metering (D1) =========================
 * Supersedes the older KV gate above, which is now unused.
 *
 * KV caches reads at the edge and is eventually consistent, so a
 * read-modify-write counter loses increments under any real concurrency —
 * measured against production on 2026-08-29: seven consecutive calls moved
 * the counter by three, and once moved it backwards. D1 does the read, the
 * increment and the return in ONE statement inside ONE transaction, so no
 * increment can be lost. Proven on security-intel in production the same day:
 * 731 calls fired, 731 counted, and every call past 100 refused — no leaks,
 * no false refusals.
 *
 * Binding QUOTA_DB -> database "datakoot-quota", table:
 *   quota(k TEXT PRIMARY KEY, period TEXT NOT NULL,
 *         n INTEGER NOT NULL, updated INTEGER NOT NULL DEFAULT 0)
 * One row per caller, reused across periods, so the table grows with the
 * number of distinct callers rather than with time.
 *
 * dkGate() returns { allowed, message, headers, meta }.
 * ========================================================================= */
const DK_FREE_LIMIT = 100;        // anonymous, keyless, per UTC day
const DK_PRO_INCLUDED = 50000;    // calls included in Pro each month
const DK_CHECKOUT = "https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf";
const DK_POLAR_ORG = "7f455043-0b15-4a1c-b7a0-9c06c9f3b95e";
const DK_BUMP_SQL =
  "INSERT INTO quota (k, period, n, updated) VALUES (?1, ?2, 1, ?3) " +
  "ON CONFLICT(k) DO UPDATE SET " +
  "n = CASE WHEN quota.period = excluded.period THEN quota.n + 1 ELSE 1 END, " +
  "period = excluded.period, updated = excluded.updated RETURNING n";

async function dkBump(env, k, period) {
  const row = await env.QUOTA_DB.prepare(DK_BUMP_SQL).bind(k, period, Math.floor(Date.now() / 1000)).first();
  const n = row && row.n;
  if (typeof n !== "number") throw new Error("quota: no row returned");
    await dkDaily(env, k, period);
  return n;
}

/* Identify a caller without storing an identity.
 *
 * This is an HMAC, not a plain hash, and the key is a 256-bit secret held only
 * in the Worker's environment (IP_SALT). That distinction matters: a plain
 * SHA-256 of an IPv4 address is reversible by anyone who has the code, because
 * there are only 4.3 billion addresses to try. Keyed, it is not reversible
 * without the secret — which is never stored beside the data it protects.
 *
 * If IP_SALT is ever unset the function still works, unkeyed, so a missing
 * secret degrades privacy rather than taking the service down.
 */
let DK_SALT = null, DK_KEY = null;
async function dkMacKey() {
  if (!DK_KEY) {
    DK_KEY = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(DK_SALT || "dk1-unsalted"),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  }
  return DK_KEY;
}
async function dkSha96(s) {
  const b = await crypto.subtle.sign("HMAC", await dkMacKey(), new TextEncoder().encode(s));
  return [...new Uint8Array(b)].slice(0, 12).map((x) => x.toString(16).padStart(2, "0")).join("");
}

/* Headers so a developer can watch the meter instead of guessing. */
function dkHeaders(limit, remaining) {
  if (limit == null) return {};
  const t = new Date();
  return {
    "X-RateLimit-Limit": String(limit),
    "X-RateLimit-Remaining": String(remaining == null ? limit : remaining),
    "X-RateLimit-Reset": String(Math.floor(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate() + 1) / 1000)),
  };
}

async function dkGate(request, env) {
  let key = (request.headers.get("Authorization") || "").trim();
  if (key.toLowerCase().indexOf("bearer ") === 0) key = key.slice(7).trim();
  if (!key) key = (request.headers.get("X-Datakoot-Key") || "").trim();

  if (key) {
    let pro = false;
    if (env.RL) { try { if ((await env.RL.get("pk:" + (await dkSha96("dk1:" + key)))) === "1") pro = true; } catch (e) {} }
    if (!pro) {
      try {
        const vr = await fetch("https://api.polar.sh/v1/customer-portal/license-keys/validate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key: key, organization_id: DK_POLAR_ORG }),
        });
        if (vr.ok) { const _pd = await vr.json().catch(() => null); pro = !!(_pd && (!("status" in _pd) || _pd.status === "granted")); if (pro && env.RL) { try { await env.RL.put("pk:" + (await dkSha96("dk1:" + key)), "1", { expirationTtl: 3600 }); } catch (e) {} } }
      } catch (e) { /* Polar unreachable: fall through to the invalid-key branch */ }
    }
    if (!pro) {
      // A key that does not validate used to fall silently back to the free
      // tier, so a paying customer with a typo looked throttled for no reason.
      return { allowed: false, headers: dkHeaders(DK_FREE_LIMIT, 0), meta: "",
        message: "That Datakoot API key was not recognised. Check it at https://datakoot.com/pricing, or remove the Authorization header to use the free tier (" + DK_FREE_LIMIT + " calls/day, no signup)." };
    }
    // Pro: 50,000 calls a month, no daily limit. Past the monthly bucket we do
    // NOT bill overage and never hard-wall: soft-fall-back to the free daily
    // allowance for the rest of the month, or top up.
    if (env.QUOTA_DB) {
      try {
        const used = await dkBump(env, "pro:" + (await dkSha96("dk1:" + key)), new Date().toISOString().slice(0, 7));
        if (used <= DK_PRO_INCLUDED) return { allowed: true, headers: {}, meta: "", message: "" };
        // bucket spent -> fall through to the free daily meter below (soft fallback)
      } catch (e) { console.error("QUOTA error (pro):", e && e.message); return { allowed: true, headers: {}, meta: "", message: "" }; }
    } else {
      return { allowed: true, headers: {}, meta: "", message: "" };
    }
  }

  if (!env.QUOTA_DB) {
    // Fail OPEN so a misconfiguration never takes the API down — but say so.
    console.error("DATAKOOT METERING DISABLED: env.QUOTA_DB is not bound");
    return { allowed: true, headers: {}, meta: "", message: "" };
  }
  let n;
  try {
    n = await dkBump(env, "ip:" + (await dkSha96("dk1:" + (request.headers.get("CF-Connecting-IP") || "anon"))), new Date().toISOString().slice(0, 10));
  } catch (e) {
    console.error("DATAKOOT METERING ERROR, failing open:", e && e.message);
    return { allowed: true, headers: {}, meta: "", message: "" };
  }
  // The Nth call writes n = N, so call DK_FREE_LIMIT is the last one allowed
  // and call DK_FREE_LIMIT + 1 is the first one refused.
  if (n > DK_FREE_LIMIT) {
    return { allowed: false, headers: dkHeaders(DK_FREE_LIMIT, 0), meta: "",
      message: "Daily free limit reached (" + DK_FREE_LIMIT + " calls). It resets at 00:00 UTC. Datakoot Pro is " + DK_PRO_INCLUDED.toLocaleString() + " calls a month across all nine servers for $15 with no daily limit — " + DK_CHECKOUT };
  }
  const left = DK_FREE_LIMIT - n;
  return { allowed: true, headers: dkHeaders(DK_FREE_LIMIT, left), meta: "\n\n(" + left + " free calls left today)", message: "" };
}

/* Retention analytics.
 *
 * `quota` keeps ONE row per caller and overwrites it when the day rolls over,
 * so it can only ever show a caller's most recent active day. That makes the
 * most valuable question — did anyone come back tomorrow? — structurally
 * unanswerable. `daily` keeps one row per caller PER DAY instead.
 *
 * It stores exactly what `quota` stores: the same keyed, non-reversible caller
 * identifier, a date, a count. No queries, no addresses, nothing new about
 * anyone. The 04:17 retention job prunes it on the same 90-day clock, so the
 * privacy policy stays true.
 *
 * Wrapped so it can never break a caller's request: if this write fails the
 * call still succeeds and metering is unaffected. It is analytics, not billing.
 */
const DK_DAILY_SQL =
  "INSERT INTO daily (k, period, n, updated) VALUES (?1, ?2, 1, ?3) " +
  "ON CONFLICT(k, period) DO UPDATE SET n = daily.n + 1, updated = excluded.updated";
async function dkDaily(env, k, period) {
  try {
    await env.QUOTA_DB.prepare(DK_DAILY_SQL)
      .bind(k, period, Math.floor(Date.now() / 1000)).run();
  } catch (e) { /* never let analytics break a paying or free call */ }
}