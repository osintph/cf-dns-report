#!/usr/bin/env python3
"""
cf_dns_report.py

Pull authoritative DNS analytics for every zone in a Cloudflare account via the
GraphQL Analytics API, analyze it, and render a self-contained HTML dashboard
plus standalone SVG charts suitable for embedding in a blog post.

Requirements: Python 3.8+, standard library only.
Optional: `dig` on PATH for ASN enrichment (--asn), via Team Cymru's DNS service.

Environment:
  CF_API_TOKEN    Account API token with Account > Account Analytics > Read
  CF_ACCOUNT_ID   Cloudflare account ID

Examples:
  ./cf_dns_report.py                         # last 7 days, all zones
  ./cf_dns_report.py --asn --redact          # enrich sources, mask IPs for publishing
  ./cf_dns_report.py --from-json out/data.json --redact   # re-render without API calls
  ./cf_dns_report.py --zones zones.json      # map zone IDs to names explicitly

Notes:
  * DNS analytics are adaptively sampled (see sampleInterval). Aggregate counts
    are scaled estimates; individual rows are a sample and single events may be
    missing.
  * Account-level queries are limited to a 7 day window (8 days of history) on
    Free, Pro and Business plans.
"""

import argparse
import collections
import datetime as dt
import html
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4/graphql"

# --------------------------------------------------------------------------
# API layer
# --------------------------------------------------------------------------


class GQLError(Exception):
    pass


def gql(token, query):
    body = json.dumps({"query": query, "variables": {}}).encode()
    req = urllib.request.Request(
        API,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "cf-dns-report/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            payload = json.load(r)
    except urllib.error.HTTPError as e:
        raise GQLError(f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}")
    if payload.get("errors"):
        raise GQLError(json.dumps(payload["errors"])[:800])
    return payload["data"]


def groups(token, acct, start, end, dims="", extra="", limit=10000, fields=None):
    """Query dnsAnalyticsAdaptiveGroups at account level.

    dims:   space separated dimension names
    extra:  extra filter clauses, e.g. 'responseCode: "NXDOMAIN"'
    fields: override the selection set (defaults to count + dimensions)
    """
    flt = f'date_geq: "{start}", date_leq: "{end}"'
    if extra:
        flt += ", " + extra
    sel = fields or ("count" + (f" dimensions {{ {dims} }}" if dims else ""))

    def build(order):
        ob = " orderBy: [count_DESC]" if order else ""
        return (
            f'{{ viewer {{ accounts(filter: {{ accountTag: "{acct}" }}) {{ '
            f"dnsAnalyticsAdaptiveGroups(limit: {limit}, filter: {{ {flt} }}{ob}) "
            f"{{ {sel} }} }} }} }}"
        )

    try:
        data = gql(token, build(order=bool(dims)))
    except GQLError as e:
        if "orderBy" in str(e) or "order" in str(e).lower():
            data = gql(token, build(order=False))
        else:
            raise
    rows = data["viewer"]["accounts"][0]["dnsAnalyticsAdaptiveGroups"]
    rows.sort(key=lambda r: r.get("count", 0), reverse=True)
    return rows


def fetch_all(token, acct, start, end, log):
    q = {}
    plan = [
        ("total", "", "", 1),
        ("rcodes", "responseCode", "", 100),
        ("timeline", "datetimeHour responseCode", "", 10000),
        ("zones", "zoneTag responseCode", "", 10000),
        ("qtypes", "queryType responseCode", "", 1000),
        ("names", "queryName zoneTag responseCode", "", 5000),
        ("nx_names", "queryName zoneTag queryType", 'responseCode: "NXDOMAIN"', 5000),
        ("sources", "sourceIP responseCode", "", 10000),
        ("colos", "coloName", "", 500),
        ("transport", "protocol ipVersion", "", 100),
        ("nx_daily_zone", "date zoneTag", 'responseCode: "NXDOMAIN"', 5000),
    ]
    for key, dims, extra, limit in plan:
        log(f"  fetching {key} ...")
        q[key] = groups(token, acct, start, end, dims, extra, limit)

    log("  fetching latency quantiles ...")
    try:
        q["latency"] = groups(
            token, acct, start, end, limit=1,
            fields="count quantiles { processingTimeUsP50 processingTimeUsP95 processingTimeUsP99 }",
        )
    except GQLError as e:
        log(f"  latency unavailable: {e}")
        q["latency"] = []
    return q


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------


def dig_txt(name):
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", name, "TXT"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return None
    line = out.strip().splitlines()[0] if out.strip() else ""
    return line.strip('"') or None


def cymru_asn(ip):
    """IP -> (asn, prefix, cc, as_name) using Team Cymru's DNS interface."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = addr.exploded.replace(":", "")
        q = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    txt = dig_txt(q)
    if not txt:
        return None
    parts = [p.strip() for p in txt.split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else None
    prefix = parts[1] if len(parts) > 1 else ""
    cc = parts[2] if len(parts) > 2 else ""
    name = ""
    if asn:
        t2 = dig_txt(f"AS{asn}.asn.cymru.com")
        if t2:
            p2 = [p.strip() for p in t2.split("|")]
            name = p2[-1] if p2 else ""
    return {"asn": asn, "prefix": prefix, "cc": cc, "as_name": name}


def enrich_asn(ips, log, cap=150):
    if not shutil.which("dig"):
        log("  dig not found, skipping ASN enrichment")
        return {}
    res = {}
    for i, ip in enumerate(ips[:cap], 1):
        info = cymru_asn(ip)
        if info:
            res[ip] = info
        if i % 25 == 0:
            log(f"  ASN lookups {i}/{min(len(ips), cap)}")
    return res


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

WORDLIST = {
    "admin", "api", "app", "apps", "auth", "backup", "beta", "bitw", "bitwarden",
    "blog", "cdn", "ci", "cloud", "cpanel", "dashboard", "db", "demo", "dev",
    "docs", "files", "ftp", "git", "gitlab", "grafana", "help", "internal",
    "intranet", "jenkins", "jira", "kibana", "login", "m", "mail", "mobile",
    "monitor", "my", "mx", "new", "ns1", "ns2", "old", "panel", "portal",
    "prod", "remote", "secure", "server", "shop", "smtp", "sso", "stage",
    "staging", "status", "store", "support", "test", "upload", "vault", "vpn",
    "web", "webmail", "whm", "wiki", "account", "accounts", "autodiscover",
    "autoconfig", "owa", "exchange", "pop", "imap", "ns", "vps", "proxy",
}


def looks_random(label):
    if len(label) < 7 or not label.isalpha():
        return False
    vowels = sum(c in "aeiou" for c in label)
    ratio = vowels / len(label)
    return ratio < 0.25 or re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", label) is not None


def categorize(name, zone):
    n = name.lower().rstrip(".")
    z = (zone or "").lower()
    first = n.split(".")[0]
    if z and n.endswith(f"{z}.{z}"):
        return "Misconfiguration (zone appended twice)"
    if n.startswith("*."):
        return "Literal wildcard probe"
    if n.startswith("_acme-challenge"):
        return "Certificate validation (ACME DNS-01)"
    if n.startswith("_dmarc") or "._domainkey" in n or n.startswith("_mta-sts") or n.startswith("_smtp._tls"):
        return "Mail policy lookup (DMARC, DKIM)"
    if first.startswith("_"):
        return "Service discovery (_srv/_tcp)"
    if looks_random(first):
        return "Random label (wildcard detection)"
    if first in ("www", "ww", "wwww") and z and n.count(".") > z.count(".") + 1:
        return "User typo / nested www"
    if first in WORDLIST:
        return "Subdomain enumeration (wordlist)"
    if first == "www":
        return "Missing www record"
    return "Other / unknown"


def infer_zone_names(q):
    votes = collections.defaultdict(collections.Counter)
    for key in ("names", "nx_names"):
        for r in q.get(key, []):
            d = r["dimensions"]
            labels = d["queryName"].lower().rstrip(".").split(".")
            if len(labels) >= 2:
                votes[d["zoneTag"]][".".join(labels[-2:])] += r["count"]
    return {zt: c.most_common(1)[0][0] for zt, c in votes.items() if c}


def mask_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/48", strict=False))


def analyze(q, zone_map, asn_map, redact, redact_zones):
    zname = dict(zone_map)
    if redact_zones:
        alias = {}
        for i, zt in enumerate(sorted(zname, key=lambda k: zname[k])):
            alias[zt] = f"zone-{chr(97 + i % 26)}{'' if i < 26 else i // 26}.example"
        real_to_alias = {zname[zt]: alias[zt] for zt in alias}
        zname = alias
    else:
        real_to_alias = {}

    def zn(zt):
        return zname.get(zt, zt[:8] + "...")

    def scrub_name(n):
        for real, al in sorted(real_to_alias.items(), key=lambda kv: -len(kv[0])):
            n = re.sub(re.escape(real), al, n, flags=re.IGNORECASE)
        return n

    A = {}
    total = q["total"][0]["count"] if q.get("total") else 0
    A["total"] = total

    rc = collections.Counter()
    for r in q.get("rcodes", []):
        rc[r["dimensions"]["responseCode"]] += r["count"]
    A["rcodes"] = rc.most_common()
    nx = rc.get("NXDOMAIN", 0)
    A["nx_pct"] = (nx / total * 100) if total else 0

    # Timeline: hour -> {NOERROR, NXDOMAIN, OTHER}
    tl = collections.defaultdict(lambda: collections.Counter())
    for r in q.get("timeline", []):
        d = r["dimensions"]
        code = d["responseCode"]
        bucket = code if code in ("NOERROR", "NXDOMAIN") else "OTHER"
        tl[d["datetimeHour"]][bucket] += r["count"]
    A["timeline"] = sorted(tl.items())

    # Zones
    zc = collections.defaultdict(collections.Counter)
    for r in q.get("zones", []):
        d = r["dimensions"]
        zc[d["zoneTag"]][d["responseCode"]] += r["count"]
    zones = []
    for zt, c in zc.items():
        t = sum(c.values())
        zones.append({"zone": zn(zt), "total": t, "nx": c.get("NXDOMAIN", 0),
                      "nx_pct": c.get("NXDOMAIN", 0) / t * 100 if t else 0})
    zones.sort(key=lambda x: x["total"], reverse=True)
    A["zones"] = zones

    # Query types
    qt = collections.Counter()
    qt_nx = collections.Counter()
    for r in q.get("qtypes", []):
        d = r["dimensions"]
        qt[d["queryType"]] += r["count"]
        if d["responseCode"] == "NXDOMAIN":
            qt_nx[d["queryType"]] += r["count"]
    A["qtypes"] = qt.most_common()
    recon_types = ("ANY", "AXFR", "IXFR", "CAA", "HINFO", "NSEC", "NSEC3PARAM")  # DNSKEY/DS omitted: normal DNSSEC validation traffic
    A["recon_types"] = [(t, qt[t]) for t in recon_types if qt.get(t)]

    # NXDOMAIN names and categories
    nxn = collections.Counter()
    nx_zone = {}
    for r in q.get("nx_names", []):
        d = r["dimensions"]
        nxn[d["queryName"]] += r["count"]
        nx_zone[d["queryName"]] = d["zoneTag"]
    cats = collections.Counter()
    cat_examples = collections.defaultdict(list)
    top_nx = []
    for name, cnt in nxn.most_common():
        real_zone = zone_map.get(nx_zone.get(name), "")
        cat = categorize(name, real_zone)
        cats[cat] += cnt
        shown = scrub_name(name) if redact_zones else name
        if len(cat_examples[cat]) < 4:
            cat_examples[cat].append(shown)
        if len(top_nx) < 40:
            top_nx.append({"name": shown, "count": cnt, "cat": cat})
    A["nx_categories"] = cats.most_common()
    A["nx_cat_examples"] = cat_examples
    A["top_nx"] = top_nx
    A["unique_nx_names"] = len(nxn)

    # Top resolving names (NOERROR)
    ok = collections.Counter()
    for r in q.get("names", []):
        d = r["dimensions"]
        if d["responseCode"] == "NOERROR":
            ok[d["queryName"]] += r["count"]
    A["top_ok"] = [((scrub_name(n) if redact_zones else n), c) for n, c in ok.most_common(20)]
    A["unique_names"] = len({r["dimensions"]["queryName"] for r in q.get("names", [])})

    # Sources
    sc = collections.defaultdict(collections.Counter)
    for r in q.get("sources", []):
        d = r["dimensions"]
        sc[d["sourceIP"]][d["responseCode"]] += r["count"]
    srcs = []
    for ip, c in sc.items():
        t = sum(c.values())
        srcs.append({"ip": ip, "total": t, "nx": c.get("NXDOMAIN", 0),
                     "nx_pct": c.get("NXDOMAIN", 0) / t * 100 if t else 0})
    srcs.sort(key=lambda x: x["total"], reverse=True)
    A["unique_sources"] = len(srcs)

    asn_tot = collections.Counter()
    asn_label = {}
    for s in srcs:
        info = asn_map.get(s["ip"])
        if info and info.get("asn"):
            key = info["asn"]
            asn_tot[key] += s["total"]
            asn_label[key] = f"AS{key} {info.get('as_name', '')[:40]}".strip()
        s["asn"] = (f"AS{info['asn']} {info.get('as_name', '')}".strip() if info and info.get("asn") else "")
        s["cc"] = info.get("cc", "") if info else ""
    A["asn_top"] = [(asn_label[a], c) for a, c in asn_tot.most_common(15)]

    probes = [s for s in srcs if s["nx"] >= 5 and s["nx_pct"] >= 50]
    probes.sort(key=lambda x: x["nx"], reverse=True)
    for lst in (srcs, probes):
        for s in lst:
            s["shown_ip"] = mask_ip(s["ip"]) if redact else s["ip"]
    A["top_sources"] = srcs[:25]
    A["probe_sources"] = probes[:25]

    A["colos"] = [(r["dimensions"]["coloName"], r["count"]) for r in q.get("colos", [])][:20]
    A["transport"] = [(f'{r["dimensions"]["protocol"]} / IPv{r["dimensions"]["ipVersion"]}', r["count"])
                      for r in q.get("transport", [])]

    # Heatmap: day x zone NXDOMAIN
    days = sorted({r["dimensions"]["date"] for r in q.get("nx_daily_zone", [])})
    hz = collections.defaultdict(dict)
    for r in q.get("nx_daily_zone", []):
        d = r["dimensions"]
        hz[zn(d["zoneTag"])][d["date"]] = r["count"]
    zorder = sorted(hz, key=lambda z: sum(hz[z].values()), reverse=True)[:15]
    A["heatmap"] = {"days": days, "zones": zorder, "cells": hz}

    lat = q.get("latency") or []
    if lat and lat[0].get("quantiles"):
        qq = lat[0]["quantiles"]
        A["latency"] = {k: qq.get(f"processingTimeUs{k}") for k in ("P50", "P95", "P99")}
    else:
        A["latency"] = {}
    return A


# --------------------------------------------------------------------------
# SVG rendering (standalone, explicit colors so files work outside the page)
# --------------------------------------------------------------------------

INK = "#1d2433"
MUTED = "#6b7385"
GRID = "#e6e8ee"
C_OK = "#2f6fdf"
C_NX = "#e0603a"
C_OTHER = "#9aa3b5"
PALETTE = ["#2f6fdf", "#e0603a", "#1f9e89", "#c2417d", "#d9a21b", "#6a4fc9",
           "#3a9bd9", "#7a8b2e", "#b5652b", "#4f5b73"]
FONT = "font-family=\"Inter, 'Segoe UI', Helvetica, Arial, sans-serif\""


def esc(s):
    return html.escape(str(s), quote=True)


def fmt(n):
    if n is None:
        return "n/a"
    n = float(n)
    for unit, div in (("M", 1e6), ("k", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.1f}{unit}"
    return f"{int(n):,}" if n == int(n) else f"{n:.1f}"


def svg_wrap(w, h, body, title):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
        f'role="img" aria-label="{esc(title)}" {FONT}>'
        f'<rect width="{w}" height="{h}" fill="#ffffff"/>'
        f'<text x="20" y="30" font-size="16" font-weight="600" fill="{INK}">{esc(title)}</text>'
        f"{body}</svg>"
    )


def nice_max(v):
    if v <= 0:
        return 1
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def svg_hbar(items, title, color=C_OK, w=760, label_w=260, max_items=15, colors=None):
    items = items[:max_items]
    if not items:
        return svg_wrap(w, 80, f'<text x="20" y="60" font-size="13" fill="{MUTED}">No data</text>', title)
    row = 26
    top = 50
    h = top + row * len(items) + 20
    mx = max(v for _, v in items) or 1
    bar_w = w - label_w - 90
    parts = []
    for i, (label, val) in enumerate(items):
        y = top + i * row
        bw = max(2, val / mx * bar_w)
        lab = str(label)
        lab = lab if len(lab) <= 38 else lab[:36] + "..."
        col = colors[i] if colors else color
        parts.append(
            f'<text x="{label_w - 10}" y="{y + 17}" font-size="12" fill="{INK}" text-anchor="end">{esc(lab)}</text>'
            f'<rect x="{label_w}" y="{y + 4}" width="{bw:.1f}" height="17" rx="3" fill="{col}"/>'
            f'<text x="{label_w + bw + 6:.1f}" y="{y + 17}" font-size="12" fill="{MUTED}">{fmt(val)}</text>'
        )
    return svg_wrap(w, h, "".join(parts), title)


def svg_timeline(timeline, title, w=980, h=320):
    if not timeline:
        return svg_wrap(w, 80, f'<text x="20" y="60" font-size="13" fill="{MUTED}">No data</text>', title)
    left, right, top, bottom = 60, 20, 60, 50
    pw, ph = w - left - right, h - top - bottom
    n = len(timeline)
    totals = [sum(c.values()) for _, c in timeline]
    step = nice_max(max(totals) / 5)
    ticks = max(1, math.ceil(max(totals) / step))
    mx = step * ticks
    bw = pw / n
    parts = []
    for i in range(ticks + 1):
        v = step * i
        y = top + ph - ph * i / ticks
        parts.append(f'<line x1="{left}" x2="{w - right}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GRID}"/>'
                     f'<text x="{left - 8}" y="{y + 4:.1f}" font-size="11" fill="{MUTED}" text-anchor="end">{fmt(v)}</text>')
    last_day = None
    for i, (hour, c) in enumerate(timeline):
        x = left + i * bw
        y = top + ph
        for key, col in (("NOERROR", C_OK), ("NXDOMAIN", C_NX), ("OTHER", C_OTHER)):
            v = c.get(key, 0)
            if not v:
                continue
            bh = v / mx * ph
            y -= bh
            parts.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{max(bw - 0.6, 0.6):.2f}" height="{bh:.2f}" fill="{col}"/>')
        day = hour[:10]
        if day != last_day:
            parts.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{top}" y2="{top + ph + 6}" stroke="{GRID}"/>'
                         f'<text x="{x + 3:.1f}" y="{top + ph + 20}" font-size="11" fill="{MUTED}">{esc(day[5:])}</text>')
            last_day = day
    lx = w - right - 330
    for j, (lab, col) in enumerate((("NOERROR", C_OK), ("NXDOMAIN", C_NX), ("Other", C_OTHER))):
        parts.append(f'<rect x="{lx + j * 110}" y="20" width="12" height="12" rx="2" fill="{col}"/>'
                     f'<text x="{lx + j * 110 + 18}" y="31" font-size="12" fill="{INK}">{lab}</text>')
    parts.append(f'<text x="{left}" y="{h - 12}" font-size="11" fill="{MUTED}">Queries per hour (UTC)</text>')
    return svg_wrap(w, h, "".join(parts), title)


def svg_donut(items, title, w=480, h=300):
    items = [(k, v) for k, v in items if v > 0]
    total = sum(v for _, v in items) or 1
    cx, cy, r, ri = 140, 170, 100, 60
    parts = []
    ang = -math.pi / 2
    shown = items[:7]
    rest = sum(v for _, v in items[7:])
    if rest:
        shown.append(("Other", rest))
    for i, (lab, v) in enumerate(shown):
        frac = v / total
        a2 = ang + frac * 2 * math.pi
        col = PALETTE[i % len(PALETTE)]
        if frac >= 0.9999:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r + ri) / 2}" fill="none" stroke="{col}" stroke-width="{r - ri}"/>')
        else:
            large = 1 if frac > 0.5 else 0
            x1, y1 = cx + r * math.cos(ang), cy + r * math.sin(ang)
            x2, y2 = cx + r * math.cos(a2), cy + r * math.sin(a2)
            x3, y3 = cx + ri * math.cos(a2), cy + ri * math.sin(a2)
            x4, y4 = cx + ri * math.cos(ang), cy + ri * math.sin(ang)
            parts.append(f'<path d="M{x1:.2f},{y1:.2f} A{r},{r} 0 {large} 1 {x2:.2f},{y2:.2f} '
                         f'L{x3:.2f},{y3:.2f} A{ri},{ri} 0 {large} 0 {x4:.2f},{y4:.2f} Z" fill="{col}" stroke="#fff" stroke-width="1.5"/>')
        ly = 80 + i * 26
        parts.append(f'<rect x="270" y="{ly}" width="12" height="12" rx="2" fill="{col}"/>'
                     f'<text x="290" y="{ly + 11}" font-size="12" fill="{INK}">{esc(lab)}</text>'
                     f'<text x="{w - 20}" y="{ly + 11}" font-size="12" fill="{MUTED}" text-anchor="end">{frac * 100:.1f}%</text>')
        ang = a2
    parts.append(f'<text x="{cx}" y="{cy - 2}" font-size="18" font-weight="600" fill="{INK}" text-anchor="middle">{fmt(total)}</text>'
                 f'<text x="{cx}" y="{cy + 16}" font-size="11" fill="{MUTED}" text-anchor="middle">queries</text>')
    return svg_wrap(w, h, "".join(parts), title)


def svg_heatmap(hm, title, w=980):
    days, zones, cells = hm["days"], hm["zones"], hm["cells"]
    if not days or not zones:
        return svg_wrap(w, 80, f'<text x="20" y="60" font-size="13" fill="{MUTED}">No data</text>', title)
    left, top, cell_h = 240, 70, 28
    cw = (w - left - 30) / len(days)
    h = top + cell_h * len(zones) + 40
    mx = max((v for z in zones for v in cells[z].values()), default=1) or 1
    parts = []
    for j, d in enumerate(days):
        parts.append(f'<text x="{left + j * cw + cw / 2:.1f}" y="{top - 10}" font-size="11" fill="{MUTED}" text-anchor="middle">{esc(d[5:])}</text>')
    for i, z in enumerate(zones):
        y = top + i * cell_h
        parts.append(f'<text x="{left - 10}" y="{y + 18}" font-size="12" fill="{INK}" text-anchor="end">{esc(z)}</text>')
        for j, d in enumerate(days):
            v = cells[z].get(d, 0)
            t = (v / mx) ** 0.5 if v else 0
            r = int(255 - t * (255 - 224))
            g = int(255 - t * (255 - 96))
            b = int(255 - t * (255 - 58))
            fill = f"rgb({r},{g},{b})" if v else "#f4f5f8"
            tc = "#ffffff" if t > 0.6 else INK
            parts.append(f'<rect x="{left + j * cw + 1:.1f}" y="{y + 1}" width="{cw - 2:.1f}" height="{cell_h - 2}" rx="3" fill="{fill}"/>')
            if v:
                parts.append(f'<text x="{left + j * cw + cw / 2:.1f}" y="{y + 18}" font-size="11" fill="{tc}" text-anchor="middle">{fmt(v)}</text>')
    parts.append(f'<text x="20" y="{h - 14}" font-size="11" fill="{MUTED}">NXDOMAIN responses per zone per day (UTC). Darker means more failed lookups.</text>')
    return svg_wrap(w, h, "".join(parts), title)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

CSS = """
:root{--ink:#1d2433;--muted:#6b7385;--line:#e6e8ee;--bg:#f6f7fa;--card:#fff;--accent:#2f6fdf;--warn:#e0603a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 Inter,'Segoe UI',Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 16px 64px}
header h1{margin:0 0 4px;font-size:28px;letter-spacing:-.01em}
header p{margin:0;color:var(--muted)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi .v{font-size:24px;font-weight:650}
.kpi .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:18px 0}
section h2{margin:0 0 6px;font-size:19px}
section .why{color:var(--muted);margin:0 0 14px;max-width:820px}
.chart{overflow-x:auto}
.chart svg{max-width:100%;height:auto;display:block}
.dl{font-size:12px;color:var(--accent);text-decoration:none}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:820px){.grid2{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
td.n{text-align:right;font-variant-numeric:tabular-nums}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#f1f3f7;padding:1px 5px;border-radius:4px;word-break:break-all}
.pill{display:inline-block;font-size:11px;padding:2px 8px;border-radius:99px;background:#eef2fb;color:#2a4a8a;white-space:nowrap}
.pill.w{background:#fdeee8;color:#9a3a1d}
footer{color:var(--muted);font-size:12.5px;margin-top:28px}
"""


def chart_block(svg, fname, outdir):
    with open(os.path.join(outdir, "charts", fname), "w") as f:
        f.write(svg)
    return f'<div class="chart">{svg}</div><a class="dl" href="charts/{fname}" download>Download SVG</a>'


def render(A, meta, outdir):
    os.makedirs(os.path.join(outdir, "charts"), exist_ok=True)
    S = []

    lat = A["latency"].get("P50")
    kpis = [
        (fmt(A["total"]), "Total queries"),
        (f'{A["nx_pct"]:.1f}%', "NXDOMAIN share"),
        (fmt(len(A["zones"])), "Zones"),
        (fmt(A["unique_names"]), "Distinct names (sample)"),
        (fmt(A["unique_sources"]), "Source IPs (sample)"),
        (f"{lat / 1000:.2f} ms" if lat else "n/a", "Median processing"),
    ]
    kpi_html = "".join(f'<div class="kpi"><div class="v">{esc(v)}</div><div class="l">{esc(l)}</div></div>' for v, l in kpis)

    S.append(f"""<section><h2>Query volume over time</h2>
<p class="why">Every lookup for any of these domains, hour by hour. Steady daily rhythm is resolvers refreshing caches as real users visit. Sudden orange spikes are bursts of lookups for names that do not exist, which is what subdomain brute forcing looks like from the authoritative side.</p>
{chart_block(svg_timeline(A["timeline"], "DNS queries per hour by response"), "01_timeline.svg", outdir)}</section>""")

    S.append(f"""<section><div class="grid2"><div><h2>Response codes</h2>
<p class="why">NOERROR means the name existed. NXDOMAIN means someone asked for a name that does not exist: typos, stale links, or reconnaissance.</p>
{chart_block(svg_donut(A["rcodes"], "Response code mix"), "02_rcodes.svg", outdir)}</div>
<div><h2>Record types requested</h2>
<p class="why">What clients wanted to know. A and AAAA are browsing, MX and TXT are mail systems and verification, and types like ANY or CAA lean toward tooling. Heavy DNSKEY traffic is DNSSEC validation, not recon.</p>
{chart_block(svg_hbar(A["qtypes"], "Query types", label_w=120, w=480, max_items=12), "03_qtypes.svg", outdir)}</div></div></section>""")

    zone_items = [(z["zone"], z["total"]) for z in A["zones"]]
    zrows = "".join(
        f'<tr><td>{esc(z["zone"])}</td><td class="n">{z["total"]:,}</td><td class="n">{z["nx"]:,}</td><td class="n">{z["nx_pct"]:.1f}%</td></tr>'
        for z in A["zones"])
    S.append(f"""<section><h2>Per-zone traffic</h2>
<p class="why">Which domains attract attention. A high NXDOMAIN rate on a small or defensive domain usually means it is being probed or mistyped far more than it is used.</p>
{chart_block(svg_hbar(zone_items, "Queries per zone"), "04_zones.svg", outdir)}
<table><tr><th>Zone</th><th>Queries</th><th>NXDOMAIN</th><th>NX rate</th></tr>{zrows}</table></section>""")

    S.append(f"""<section><h2>When failed lookups happen</h2>
<p class="why">NXDOMAIN volume per zone per day. Enumeration runs show up as one hot cell; a misconfiguration or a broken link shows up as a steady band across every day.</p>
{chart_block(svg_heatmap(A["heatmap"], "NXDOMAIN heatmap"), "05_heatmap.svg", outdir)}</section>""")

    cat_colors = [PALETTE[i % len(PALETTE)] for i in range(len(A["nx_categories"]))]
    crow = "".join(
        f'<tr><td>{esc(c)}</td><td class="n">{n:,}</td><td>{", ".join(f"<code>{esc(e)}</code>" for e in A["nx_cat_examples"].get(c, []))}</td></tr>'
        for c, n in A["nx_categories"])
    S.append(f"""<section><h2>What the failed lookups are</h2>
<p class="why">Every name that returned NXDOMAIN, sorted into intent buckets by pattern. This is the core of what DNS telemetry reveals: who is guessing, what they expect you to run, and where your own configuration leaks.</p>
{chart_block(svg_hbar(A["nx_categories"], "NXDOMAIN by inferred intent", colors=cat_colors, label_w=320), "06_nx_categories.svg", outdir)}
<table><tr><th>Category</th><th>Queries</th><th>Examples</th></tr>{crow}</table></section>""")

    nrows = "".join(
        f'<tr><td><code>{esc(r["name"])}</code></td><td class="n">{r["count"]:,}</td><td><span class="pill">{esc(r["cat"])}</span></td></tr>'
        for r in A["top_nx"])
    S.append(f"""<section><h2>Most requested names that do not exist</h2>
<p class="why">The raw list behind the categories. Look for names you recognise: an old service, a typo in your own docs, or a hostname you only ever used internally.</p>
<table><tr><th>Name</th><th>Queries</th><th>Category</th></tr>{nrows}</table></section>""")

    def src_rows(lst):
        return "".join(
            f'<tr><td><code>{esc(s["shown_ip"])}</code></td><td>{esc(s.get("asn", ""))}</td><td>{esc(s.get("cc", ""))}</td>'
            f'<td class="n">{s["total"]:,}</td><td class="n">{s["nx"]:,}</td>'
            f'<td class="n"><span class="pill{" w" if s["nx_pct"] >= 50 else ""}">{s["nx_pct"]:.0f}%</span></td></tr>'
            for s in lst)

    hdr = "<tr><th>Source</th><th>ASN</th><th>CC</th><th>Queries</th><th>NXDOMAIN</th><th>NX rate</th></tr>"
    asn_chart = ""
    if A["asn_top"]:
        asn_chart = chart_block(svg_hbar(A["asn_top"], "Queries by source network (ASN)", label_w=320), "07_asn.svg", outdir)
    S.append(f"""<section><h2>Who is asking</h2>
<p class="why">The source seen by an authoritative server is almost always a recursive resolver (an ISP, Google, Cloudflare, Quad9), not the person behind it. Big public resolvers dominate. Sources with mostly failed lookups and modest volume are the interesting ones: tooling talking to your nameservers directly, or a resolver serving a single noisy scanner.</p>
{asn_chart}
<h3>Top sources by volume</h3><table>{hdr}{src_rows(A["top_sources"])}</table>
<h3>Probe-like sources (mostly NXDOMAIN)</h3><table>{hdr}{src_rows(A["probe_sources"]) or '<tr><td colspan="6">None above threshold</td></tr>'}</table></section>""")

    S.append(f"""<section><div class="grid2"><div><h2>Where queries land</h2>
<p class="why">Cloudflare data centers that answered. Anycast routes each resolver to its nearest site, so this is a rough map of where the asking resolvers sit.</p>
{chart_block(svg_hbar(A["colos"], "Answering data center", label_w=90, w=480, max_items=15), "08_colos.svg", outdir)}</div>
<div><h2>Transport</h2>
<p class="why">UDP is normal. TCP shows up for large answers, zone transfer attempts and some tooling. The IPv6 share shows how much resolver traffic already runs over v6.</p>
{chart_block(svg_hbar(A["transport"], "Protocol and IP version", label_w=130, w=480), "09_transport.svg", outdir)}</div></div></section>""")

    if A["recon_types"]:
        rt = "".join(f"<tr><td><code>{esc(t)}</code></td><td class='n'>{c:,}</td></tr>" for t, c in A["recon_types"])
        S.append(f"""<section><h2>Recon-flavoured record types</h2>
<p class="why">Record types normal browsing rarely touches. Non-zero counts are not proof of anything, but they are where to look first.</p>
<table><tr><th>Type</th><th>Queries</th></tr>{rt}</table></section>""")

    okrows = "".join(f'<tr><td><code>{esc(n)}</code></td><td class="n">{c:,}</td></tr>' for n, c in A["top_ok"])
    S.append(f"""<section><h2>Most requested names that exist</h2>
<p class="why">The baseline. Anything here you did not expect to be public, or did not expect to be this popular, deserves a second look.</p>
<table><tr><th>Name</th><th>Queries</th></tr>{okrows}</table></section>""")

    lat_txt = ""
    if A["latency"]:
        lat_txt = " Processing time (Cloudflare side only): " + ", ".join(
            f"{k} {v / 1000:.2f} ms" for k, v in A["latency"].items() if v is not None) + "."

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Telemetry Report</title><style>{CSS}</style></head><body><div class="wrap">
<header><h1>{esc(meta.get("title", "What your DNS logs reveal"))}</h1>
<p>Authoritative DNS analytics from Cloudflare, {esc(meta["start"])} to {esc(meta["end"])} (UTC). Generated {esc(meta["generated"])}.</p></header>
<div class="kpis">{kpi_html}</div>
{''.join(S)}
<footer>Source: Cloudflare GraphQL Analytics API, dnsAnalyticsAdaptive datasets. Data is adaptively sampled: totals are scaled estimates and per-name or per-source rows reflect a sample, so rare single events may not appear.{lat_txt}
{' Source IPs masked to /24 (IPv4) and /48 (IPv6).' if meta.get("redact") else ''}{' Zone names replaced with aliases.' if meta.get("redact_zones") else ''}</footer>
</div></body></html>"""
    path = os.path.join(outdir, "index.html")
    with open(path, "w") as f:
        f.write(doc)
    return path


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Cloudflare DNS analytics report generator")
    ap.add_argument("--days", type=int, default=7, help="days back including today (account level max 7 on non-Enterprise)")
    ap.add_argument("--out", default="dns-report", help="output directory")
    ap.add_argument("--zones", help="JSON file mapping zoneTag to domain name")
    ap.add_argument("--asn", action="store_true", help="enrich source IPs with ASN via Team Cymru (needs dig)")
    ap.add_argument("--asn-limit", type=int, default=150, help="max source IPs to enrich")
    ap.add_argument("--redact", action="store_true", help="mask source IPs to /24 and /48 for publishing")
    ap.add_argument("--redact-zones", action="store_true", help="replace zone names with aliases")
    ap.add_argument("--title", default="What your DNS logs reveal", help="report title")
    ap.add_argument("--from-json", help="re-render from a saved data.json instead of calling the API")
    args = ap.parse_args()

    def log(m):
        print(m, file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)

    if args.from_json:
        with open(args.from_json) as f:
            saved = json.load(f)
        q, asn_map, start, end = saved["raw"], saved.get("asn", {}), saved["start"], saved["end"]
        if args.asn and not asn_map:
            log("Enriching ASNs ...")
            ips = sorted({r["dimensions"]["sourceIP"] for r in q.get("sources", [])},
                         key=lambda ip: -sum(r["count"] for r in q["sources"] if r["dimensions"]["sourceIP"] == ip))
            asn_map = enrich_asn(ips, log, args.asn_limit)
    else:
        token = os.environ.get("CF_API_TOKEN")
        acct = os.environ.get("CF_ACCOUNT_ID")
        if not token or not acct:
            sys.exit("Set CF_API_TOKEN and CF_ACCOUNT_ID")
        if args.days > 7:
            log("Warning: account-level window above 7 days needs Enterprise; the API may reject it.")
        today = dt.datetime.now(dt.timezone.utc).date()
        start = str(today - dt.timedelta(days=args.days - 1))
        end = str(today)
        log(f"Querying {start} .. {end}")
        try:
            q = fetch_all(token, acct, start, end, log)
        except GQLError as e:
            sys.exit(f"API error: {e}")
        asn_map = {}
        if args.asn:
            log("Enriching ASNs ...")
            agg = collections.Counter()
            for r in q.get("sources", []):
                agg[r["dimensions"]["sourceIP"]] += r["count"]
            asn_map = enrich_asn([ip for ip, _ in agg.most_common()], log, args.asn_limit)
        with open(os.path.join(args.out, "data.json"), "w") as f:
            json.dump({"start": start, "end": end, "raw": q, "asn": asn_map}, f)
        log(f"Raw data saved to {os.path.join(args.out, 'data.json')}")

    zone_map = infer_zone_names(q)
    if args.zones:
        with open(args.zones) as f:
            zone_map.update(json.load(f))

    A = analyze(q, zone_map, asn_map, args.redact, args.redact_zones)
    meta = {
        "start": start, "end": end,
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "redact": args.redact, "redact_zones": args.redact_zones, "title": args.title,
    }
    path = render(A, meta, args.out)
    log(f"Report written to {path}")
    log(f"Charts in {os.path.join(args.out, 'charts')}/")


if __name__ == "__main__":
    main()
