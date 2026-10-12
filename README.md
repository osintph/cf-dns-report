# cf-dns-report

Pull authoritative DNS analytics for every zone in a Cloudflare account and turn them into a self-contained HTML dashboard with standalone SVG charts.

If Cloudflare runs your DNS, it already sees every lookup for your domains, including names that do not exist. Those failed lookups are where subdomain enumeration, wildcard checks, missing mail records and your own misconfigurations show up. This script gets them out of the GraphQL Analytics API with one read-only token and makes them readable.

Background and a worked example: [link to blog post]

## What you get

- `index.html`: a single-file dashboard, no external scripts or fonts
- `charts/*.svg`: nine standalone charts, numbered in reading order, ready to drop into a blog post or report
- `data.json`: the raw API results, so you can re-render later without calling the API again

The report covers:

1. Hourly query volume, stacked by response code
2. Response code mix and record types requested
3. Per-zone volume and NXDOMAIN rate
4. NXDOMAIN heatmap per zone per day
5. Failed lookups sorted into intent buckets: wordlist enumeration, wildcard probes, random-label wildcard detection, DMARC/DKIM lookups, ACME validation, doubled zone names, missing `www`
6. Most requested names that do not exist
7. Top sources and probe-like sources (mostly NXDOMAIN), with ASN and country when enriched
8. Answering Cloudflare data centers, UDP/TCP and IPv4/IPv6 split
9. Unusual record types and the most requested names that do exist

## Requirements

- Python 3.8 or later, standard library only
- `dig` on your PATH, only if you use `--asn`
- Cloudflare as the authoritative DNS for your zones (any plan, including Free)

## Setup

Create an Account API token in the Cloudflare dashboard with exactly one permission:

- **Account > Account Analytics > Read**

Nothing else is needed. Restrict the token to the IP of the machine that runs the script and give it an expiry.

Your account ID is the 32 character hex string in the dashboard URL after `dash.cloudflare.com/`.

```bash
export CF_ACCOUNT_ID="your_account_id"
read -rs CF_API_TOKEN && export CF_API_TOKEN
```

`read -rs` keeps the token out of your shell history.

## Usage

```bash
chmod +x cf_dns_report.py

# Last 7 days, all zones
./cf_dns_report.py --out dns-report

# Add ASN and country for the top sources
./cf_dns_report.py --asn --out dns-report

# Re-render a saved run with source IPs masked, for publishing
./cf_dns_report.py --from-json dns-report/data.json --out dns-report-public --redact

# Also replace zone names with zone-a.example style aliases
./cf_dns_report.py --from-json dns-report/data.json --out dns-report-public --redact --redact-zones
```

| Flag | Default | Description |
| --- | --- | --- |
| `--days` | `7` | Days back, including today |
| `--out` | `dns-report` | Output directory |
| `--asn` | off | Enrich source IPs with ASN, prefix and country via Team Cymru's DNS service |
| `--asn-limit` | `150` | Maximum number of source IPs to enrich, busiest first |
| `--redact` | off | Mask source IPs to /24 (IPv4) and /48 (IPv6) |
| `--redact-zones` | off | Replace zone names with aliases everywhere in the report |
| `--zones` | none | JSON file mapping zone ID to domain name, see `zones.example.json` |
| `--title` | `What your DNS logs reveal` | Report title |
| `--from-json` | none | Render from a saved `data.json` instead of calling the API |

Zone IDs are mapped to domain names automatically from the query names. If one comes out wrong, pass `--zones`.

## Limits worth knowing

- **Data is sampled.** Cloudflare's DNS analytics are adaptively sampled. Totals are scaled estimates; individual names and sources are a sample, and a single rare lookup may not appear.
- **History is short.** Account-wide queries return 8 days of history, in a window of up to 7 days, on Free, Pro and Business plans. Enterprise gets 62 days. Run the script on a schedule and keep `data.json` if you want a longer view.
- **Sources are resolvers.** The source IP is almost always a recursive resolver, not the person behind the lookup.
- **Heavy DNSKEY traffic is normal** on DNSSEC-signed zones. It is validation, not reconnaissance, and the report does not flag it.
- **ASN enrichment sends IPs to Team Cymru.** `--asn` resolves each source address against `origin.asn.cymru.com` through your configured resolver.

## Privacy

`data.json` and the unredacted report contain source IP addresses and every name queried in your zones, including names you may not want public. The `.gitignore` keeps them out of git. Use `--redact` and `--redact-zones` before sharing a report.

## References

- [Cloudflare DNS: Analytics and logs](https://developers.cloudflare.com/dns/additional-options/analytics/)
- [Configure an Analytics API token](https://developers.cloudflare.com/analytics/graphql-api/getting-started/authentication/api-token-auth/)
- [Team Cymru IP to ASN mapping](https://team-cymru.com/community-services/ip-asn-mapping/)

## License

MIT. See `LICENSE`.
