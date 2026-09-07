# Domain & Company Intel MCP — by Datakoot

Domain and company intelligence for AI agents. Give an agent a domain or email address and it can vet the company, qualify the lead, or map the target — all from free public data, no API keys.

## Tools

| Tool | What it does | Source |
|---|---|---|
| `domain_intel` | Registrar, creation/expiry dates, domain age, EPP status, nameservers, DNSSEC, abuse contact | RDAP |
| `dns_lookup` | A, AAAA, MX, NS, TXT, CNAME, SOA records | Cloudflare DoH |
| `email_deliverability` | MX presence, SPF/DMARC posture, free vs. disposable provider, verdict | Cloudflare DoH |
| `tech_stack` | Web server, CMS/framework, CDN, analytics, security headers, page title | Live fetch |
| `subdomains` | Subdomain discovery from Certificate Transparency logs | crt.sh |
| `domain_report` | One call returns a full dossier: registration + DNS + email deliverability + tech stack, combined | all-in-one |

No API keys required for any tool.

## Quick start (hosted)

**Claude Code**

```bash
claude mcp add --transport http domain-intel https://domain.datakoot.com/mcp
```

**Claude Desktop / other clients**

```json
{
  "mcpServers": {
    "domain-intel": {
      "command": "npx",
      "args": ["mcp-remote", "https://domain.datakoot.com/mcp"]
    }
  }
}
```

## Try it in 10 seconds — no key, no signup

Paste this into a terminal:

```bash
curl -s https://domain.datakoot.com/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "tech_stack", "arguments": {"domain": "stripe.com"}}}'
```

You get the detected technology stack behind stripe.com — no API key, nothing to sign up for.

Or point any MCP client at the URL and just ask your agent, in plain language:

- "What tech stack does stripe.com run on?"
- "Is this domain's email configured to prevent spoofing?"


## Example agent workflows

- *"Is acme.com a real, established business? When was it registered?"* → `domain_intel`
- *"This lead’s email is @acme.io — can it receive mail, is it a throwaway?"* → `email_deliverability`
- *"What’s competitor.com built on?"* → `tech_stack`
- *"Map the public subdomains of target.com"* → `subdomains`

## Pricing

**Free** — 100 calls a day, keyless, no signup. **Pro** — $15/mo including 50,000 calls a month with no daily limit; one key unlocks all nine Datakoot servers. Go over the monthly allowance and you drop to free-tier speed for the rest of the month, or top up — never cut off, no metered overage. Full terms: [datakoot.com/pricing](https://datakoot.com/pricing).

Result lists are capped at 10 items per call on Free and uncapped on Pro.

All six tools work on the free tier with no key. A paid allowance is shared
across all nine Datakoot servers rather than being nine separate buckets, and
only a `tools/call` counts — connecting and listing tools are free. Full terms at
[datakoot.com/pricing](https://datakoot.com/pricing).

**[Subscribe →](https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf)** — one subscription unlocks Pro on every Datakoot server.

### Using your Pro key

After subscribing you receive a licence key. Pass it as a Bearer token and the free-tier caps are removed:

```bash
claude mcp add --transport http --header "Authorization: Bearer YOUR-KEY" domain-intel https://domain.datakoot.com/mcp
```

The key is validated against Polar on each request (cached briefly). Cancel anytime — access reverts to the free tier automatically.

## Self-host (Cloudflare Workers, free tier)

The `worker.js` in this repository is a snapshot of the hosted server, not a live mirror of it — the hosted endpoint is deployed independently and may be ahead. Create a Worker, paste `worker.js`, deploy.

## License

MIT. Data from RDAP, Cloudflare DNS, and crt.sh under their respective terms.
