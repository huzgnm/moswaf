#!/usr/bin/env python3
"""
MosWAF - turn a SafeLine config dump into MosWAF site records.

Reads the `nginx -T` output produced by scripts/safeline-export.sh and writes one
JSON body per site, ready for POST /api/sites. It does not touch SafeLine and it
does not create anything by itself unless you ask it to with --post.

    python3 safeline-import.py ~/moswaf-migration/safeline-*/nginx-T.conf \
        --certs-from ~/moswaf-migration/safeline-*/certs

    # then, against a MosWAF that is already running:
    export MOSWAF_TOKEN=...            # from POST /api/auth/login
    python3 safeline-import.py ... --post https://127.0.0.1:9445

What it deliberately will not do:

  * Invent an upstream. A site whose proxy_pass is not in the dump is reported as
    unmigratable and left out of the output. A site pointed at the wrong backend
    is worse than a site not migrated.
  * Turn on force_https. While SafeLine still owns 443 a redirect from the staged
    MosWAF sends the visitor to SafeLine, and the test tells you nothing. The
    sites that had a redirect are listed at the end; turn it on after cutover, or
    pass --keep-force-https if MosWAF already owns 443.
"""

import argparse
import glob
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

# ----------------------------------------------------------------- the parser
#
# nginx configuration is a tree of `directive args;` and `directive args { ... }`.
# Small enough to read properly, and worth doing: a regex over server_name lines
# cannot tell which proxy_pass belongs to which server, which is the one thing
# this whole script exists to get right.


def tokenize(text):
    tokens, buf, i, n = [], [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "\"'":
            quote, i, s = c, i + 1, []
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    s.append(text[i + 1])
                    i += 2
                    continue
                s.append(text[i])
                i += 1
            i += 1
            buf.append("".join(s))
        elif c.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
            i += 1
        elif c in "{};":
            if buf:
                tokens.append("".join(buf))
                buf = []
            tokens.append(c)
            i += 1
        else:
            buf.append(c)
            i += 1
    if buf:
        tokens.append("".join(buf))
    return tokens


def parse(tokens, i=0):
    """Returns (nodes, next_index); a node is (args, children or None)."""
    nodes, args = [], []
    while i < len(tokens):
        t = tokens[i]
        if t == ";":
            if args:
                nodes.append((args, None))
            args, i = [], i + 1
        elif t == "{":
            children, i = parse(tokens, i + 1)
            nodes.append((args, children))
            args = []
        elif t == "}":
            return nodes, i + 1
        else:
            args.append(t)
            i += 1
    return nodes, i


def walk(nodes, name):
    """Every block called `name`, at any depth."""
    for args, children in nodes:
        if children is None:
            continue
        if args and args[0] == name:
            yield args, children
        yield from walk(children, name)


def directives(nodes, name):
    for args, children in nodes:
        if children is None and args and args[0] == name:
            yield args


# -------------------------------------------------------------- the extraction

UPSTREAM_RE = re.compile(r"^(https?)://([^/;]+)")


def find_proxy_pass(nodes):
    """The proxy_pass that serves the site, ignoring the WAF's own plumbing.

    SafeLine gives every application a dozen extra locations - error pages on a
    unix socket, its own challenge endpoint - and the one that matters is
    `location ^~ /`. So: skip `internal` blocks and unix sockets, and prefer the
    location whose path is `/` whatever prefix modifier it carries.
    """
    best, fallback = None, None
    for args, children in walk(nodes, "location"):
        if next(directives(children, "internal"), None) is not None:
            continue
        target = next((d[1] for d in directives(children, "proxy_pass") if len(d) > 1), None)
        if not target or "//unix:" in target:
            continue
        # `location [modifier] path` - the path is always the last argument.
        modifier = args[1] if len(args) > 2 else ""
        path = args[-1] if len(args) > 1 else ""
        if path == "/" and modifier != "=":
            best = target
        elif fallback is None:
            fallback = target
    if best:
        return best
    # A proxy_pass can also sit directly in the server block.
    for d in directives(nodes, "proxy_pass"):
        if len(d) > 1 and "//unix:" not in d[1]:
            return d[1]
    return fallback


def resolve_upstream(target, upstreams, loopback_host):
    """`http://backend_3` or `https://10.0.0.5:8080` -> (scheme, host, port, note)."""
    m = UPSTREAM_RE.match(target or "")
    if not m:
        return None
    scheme, authority = m.group(1), m.group(2)
    note = ""

    # SafeLine usually names an upstream block and puts the real address in it.
    if authority in upstreams:
        servers = upstreams[authority]
        if not servers:
            return None
        if len(servers) > 1:
            note = "upstream had %d servers; took the first (%s)" % (
                len(servers),
                ", ".join(servers),
            )
        authority = servers[0]

    if authority.startswith("["):  # IPv6 literal
        host, _, rest = authority.partition("]")
        host = host[1:]
        port = rest.lstrip(":")
    else:
        host, _, port = authority.partition(":")

    port = int(port) if port.isdigit() else (443 if scheme == "https" else 80)

    # MosWAF's proxy runs in a bridge network, so a backend SafeLine reached on
    # 127.0.0.1 (host networking) is not reachable at that address any more.
    if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        note = ("upstream was %s; rewritten to %s. Check this is the right backend."
                % (host, loopback_host))
        host = loopback_host

    return scheme, host, port, note


def read_cert(path, certs_dir):
    """The certificate as it was on SafeLine, looked up by the path the config names."""
    for candidate in filter(None, [path,
                                   os.path.join(certs_dir, os.path.basename(path)) if certs_dir else None]):
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r") as fh:
                    return fh.read(), candidate
            except OSError:
                pass
    if certs_dir:
        for found in glob.glob(os.path.join(certs_dir, "**", os.path.basename(path)), recursive=True):
            with open(found, "r") as fh:
                return fh.read(), found
    return None, None


SKIP_NAMES = {"_", "*", "localhost", ""}


def names_from_dump(sql_path):
    """domain -> the name the owner gave the application in SafeLine.

    `nginx -T` knows the domains but not what the site is called; the label lives
    in SafeLine's own database. Reading it from the pg_dump keeps the site list on
    MosWAF recognisable instead of a column of bare hostnames.
    """
    labels = {}
    try:
        with open(sql_path, "r", errors="replace") as fh:
            in_block = False
            for line in fh:
                if line.startswith("COPY public.mgt_website "):
                    in_block = True
                    continue
                if not in_block:
                    continue
                if line.startswith("\\."):
                    break
                fields = line.rstrip("\n").split("\t")
                if len(fields) < 6:
                    continue
                comment = fields[4].strip()
                if comment in ("", "\\N"):
                    continue
                try:
                    for domain in json.loads(fields[5]):
                        labels[domain] = comment
                except (ValueError, TypeError):
                    continue
    except OSError as e:
        sys.stderr.write("  ! could not read %s (%s); falling back to domain names\n" % (sql_path, e))
    return labels


def extract(nodes, loopback_host):
    upstreams = {}
    for args, children in walk(nodes, "upstream"):
        if len(args) > 1:
            upstreams[args[1]] = [d[1] for d in directives(children, "server") if len(d) > 1]

    servers = []
    for _, children in walk(nodes, "server"):
        names = []
        for d in directives(children, "server_name"):
            names.extend(n for n in d[1:] if n not in SKIP_NAMES)
        if not names:
            continue

        listens = [d[1] for d in directives(children, "listen") if len(d) > 1]
        is_ssl = any("ssl" in " ".join(d) for d in directives(children, "listen")) or \
                 any(l.endswith("443") or l == "443" for l in listens)

        redirect = any(
            len(d) > 2 and d[1] == "301" and d[2].startswith("https://")
            for _, sub in walk(children, "location")
            for d in directives(sub, "return")
        )

        cert = next((d[1] for d in directives(children, "ssl_certificate") if len(d) > 1), None)
        key = next((d[1] for d in directives(children, "ssl_certificate_key") if len(d) > 1), None)

        servers.append({
            "names": names,
            "ssl": is_ssl,
            "redirect": redirect,
            "cert": cert,
            "key": key,
            "proxy": find_proxy_pass(children),
        })

    # An application is normally two server blocks - one on 80, one on 443 - with
    # the same names. Merge them back into the one site they describe.
    merged = {}
    for s in servers:
        k = tuple(sorted(set(s["names"])))
        m = merged.setdefault(k, {"domains": list(k), "ssl": False, "redirect": False,
                                  "cert": None, "key": None, "proxy": None, "proxy_ssl": None})
        m["redirect"] = m["redirect"] or s["redirect"]
        if s["ssl"]:
            m["ssl"] = True
            m["cert"] = m["cert"] or s["cert"]
            m["key"] = m["key"] or s["key"]
            m["proxy_ssl"] = m["proxy_ssl"] or s["proxy"]
        else:
            m["proxy"] = m["proxy"] or s["proxy"]

    out = []
    for m in merged.values():
        # The HTTPS block is the one that serves; the HTTP block is often just a
        # redirect with no upstream of its own.
        m["proxy"] = m["proxy_ssl"] or m["proxy"]
        m["upstreams"] = upstreams
        out.append(m)
    return out, upstreams


# ------------------------------------------------------------------ the output


def site_name(domains, labels):
    for d in domains:
        if d in labels:
            return labels[d]
    return domains[0].lstrip("*.")


def build(args):
    with open(args.dump, "r", errors="replace") as fh:
        nodes, _ = parse(tokenize(fh.read()))

    labels = names_from_dump(args.names_from) if args.names_from else {}

    found, upstreams = extract(nodes, args.loopback_host)
    if not found:
        sys.exit("No server block with a real server_name in %s - is that the right dump?" % args.dump)

    sites, skipped, notes, had_redirect, no_cert = [], [], [], [], []

    for m in sorted(found, key=lambda x: x["domains"][0]):
        domains = m["domains"]
        resolved = resolve_upstream(m["proxy"], upstreams, args.loopback_host) if m["proxy"] else None
        if not resolved:
            skipped.append((domains, m["proxy"] or "no proxy_pass in the dump"))
            continue
        scheme, host, port, note = resolved
        if note:
            notes.append((domains[0], note))

        site = {
            "name": site_name(domains, labels),
            "domains": domains,
            "upstream_scheme": scheme,
            "upstream_host": host,
            "upstream_port": port,
            "mode": args.mode,
            "challenge": "auto",
            "rate_rps": 0,
            "rate_burst": 0,
            "force_https": bool(m["redirect"]) if args.keep_force_https else False,
        }
        if m["redirect"] and not args.keep_force_https:
            had_redirect.append(domains[0])

        if m["cert"]:
            cert, cert_src = read_cert(m["cert"], args.certs_from)
            key, _ = read_cert(m["key"], args.certs_from) if m["key"] else (None, None)
            if cert and key:
                site["tls_cert"] = cert
                site["tls_key"] = key
            else:
                no_cert.append((domains[0], "config names %s but the file was not found" % m["cert"]))
        else:
            no_cert.append((domains[0], "SafeLine served it without TLS"))

        sites.append(site)

    return sites, skipped, notes, had_redirect, no_cert


def report(sites, skipped, notes, had_redirect, no_cert, out_path):
    w = sys.stderr.write
    w("\n  %-38s %-28s %s\n" % ("DOMAINS", "UPSTREAM", "TLS"))
    w("  " + "-" * 76 + "\n")
    for s in sites:
        doms = ", ".join(s["domains"])
        if len(doms) > 37:
            doms = doms[:34] + "..."
        w("  %-38s %-28s %s\n" % (
            doms,
            "%s://%s:%d" % (s["upstream_scheme"], s["upstream_host"], s["upstream_port"]),
            "copied" if "tls_cert" in s else "-",
        ))

    w("\n  %d site(s) ready -> %s\n" % (len(sites), out_path))

    if notes:
        w("\n  Check these upstreams by hand:\n")
        for d, n in notes:
            w("    %-28s %s\n" % (d, n))
    if no_cert:
        w("\n  No certificate (they will serve HTTP only until one is installed):\n")
        for d, n in no_cert:
            w("    %-28s %s\n" % (d, n))
    if had_redirect:
        w("\n  Had an HTTP->HTTPS redirect on SafeLine. Turn force_https on for these\n"
          "  AFTER MosWAF owns port 443, not before:\n")
        for d in had_redirect:
            w("    %s\n" % d)
    if skipped:
        w("\n  NOT MIGRATED - no usable upstream in the dump. Find the real backend\n"
          "  for each of these before cutover; do not guess:\n")
        for doms, why in skipped:
            w("    %-38s %s\n" % (", ".join(doms), why))
    w("\n")


# -------------------------------------------------------------------- posting


def post_sites(api, token, sites):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the dashboard's certificate is self-signed

    created, failed = 0, []
    for s in sites:
        body = json.dumps(s).encode()
        req = urllib.request.Request(
            api.rstrip("/") + "/api/sites", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
                resp.read()
            created += 1
            sys.stderr.write("  created  %s\n" % s["domains"][0])
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:200]
            failed.append((s["domains"][0], "%s %s" % (e.code, detail)))
            sys.stderr.write("  FAILED   %s  %s %s\n" % (s["domains"][0], e.code, detail))
        except Exception as e:  # noqa: BLE001 - report whatever went wrong and carry on
            failed.append((s["domains"][0], str(e)))
            sys.stderr.write("  FAILED   %s  %s\n" % (s["domains"][0], e))
    sys.stderr.write("\n  %d created, %d failed\n\n" % (created, len(failed)))
    return 1 if failed else 0


def main():
    p = argparse.ArgumentParser(description="SafeLine config dump -> MosWAF sites")
    p.add_argument("dump", help="nginx -T output from the SafeLine proxy container")
    p.add_argument("--certs-from", default="", help="directory the certificates were copied to")
    p.add_argument("--names-from", default="",
                   help="SafeLine pg_dump, to name each site the way SafeLine did")
    p.add_argument("--out", default=os.path.expanduser("~/moswaf-migration/sites.json"),
                   help="where to write the site records (never inside the repository)")
    p.add_argument("--mode", default="monitor", choices=["monitor", "protect", "off"],
                   help="mode for every site; monitor logs and blocks nothing (default)")
    p.add_argument("--loopback-host", default="host.docker.internal",
                   help="what a 127.0.0.1 upstream becomes for MosWAF's bridge network")
    p.add_argument("--keep-force-https", action="store_true",
                   help="set force_https from SafeLine; only once MosWAF owns port 443")
    p.add_argument("--post", metavar="API_URL",
                   help="also create the sites, e.g. https://127.0.0.1:9445 (needs MOSWAF_TOKEN)")
    args = p.parse_args()

    sites, skipped, notes, had_redirect, no_cert = build(args)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(sites, fh, indent=2)
    os.chmod(args.out, 0o600)  # it holds private keys

    report(sites, skipped, notes, had_redirect, no_cert, args.out)

    if args.post:
        token = os.environ.get("MOSWAF_TOKEN", "")
        if not token:
            sys.exit("MOSWAF_TOKEN is not set. Log in to MosWAF and export the token first.")
        return post_sites(args.post, token, sites)
    return 0


if __name__ == "__main__":
    sys.exit(main())
