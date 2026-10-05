#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ATK New Technology
"""rhel-fixstate: tag Wazuh vulnerability findings on RHEL hosts with Red Hat's own status.

Reads findings from the Wazuh indexer (wazuh-states-vulnerabilities-*, read-only
GET requests) or from an exported JSON file, looks each CVE up in the Red Hat
Security Data API, and writes one CSV row per finding with Red Hat's fix_state
for the host's RHEL major version ("Will not fix", "Fix deferred", "Affected",
...) or the advisory that fixes it.

Red Hat lists *source* packages (rust-sequoia-sq) while Wazuh reports *binary*
packages (sequoia-sq). Every row says how the package was matched:

  exact         Red Hat row names the same package as the finding
  source-rpm    matched through the source RPM you supplied with --rpm-sources
  name          matched by a narrow naming rule (common sub-package suffix, or a
                rust-/python- style prefix); used only without --rpm-sources data
  product-only  no package name matched; every Red Hat row for this RHEL major
                carries the same fix_state and none is a fix, so that status is reported
  none          not matched; the label says why

Standard library only. Nothing is written to the indexer.
"""

import argparse
import base64
import csv
import getpass
import http.client
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

__version__ = "0.1.0"

RH_API = "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json"
RH_PAGE = "https://access.redhat.com/security/cve/{}"
DEFAULT_INDEX = "wazuh-states-vulnerabilities-*"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# Source package prefixes Red Hat uses for language ecosystems.
SOURCE_PREFIXES = ("rust-", "python-", "python3-", "perl-", "golang-", "nodejs-",
                   "ruby-", "rubygem-", "php-", "ghc-", "ocaml-", "lua-", "R-")
# First token after "<source>-" that marks an ordinary sub-package (openssl-libs, vim-minimal).
# Anything else (libcap-ng, rpm-sequoia, openssl-fips-provider) is not trusted as a match.
SUBPACKAGE_SUFFIXES = {
    "libs", "lib", "devel", "common", "tools", "utils", "minimal", "data", "core", "headers",
    "doc", "docs", "static", "langpack", "all", "pam", "udev", "container", "resolved", "rpm",
    "client", "server", "daemon", "plugins", "plugin", "modules", "gui", "x11", "selinux",
    "config", "debug", "extra", "extras", "base", "runtime", "help", "locale", "i18n", "bin",
    "cli", "firmware", "compat", "filesystem", "fonts", "wheel", "test", "tests", "examples",
    "contrib", "perl", "python3", "ldap", "gssapi", "krb5", "sqlite", "mysql", "pgsql", "odbc",
    "gnutls", "nss", "openssl", "gcrypt", "debuginfo", "init", "service", "sysinit", "boot",
    "dracut", "oomd", "networkd", "journal", "remote", "binutils", "cpp", "gfortran", "c++",
}
MODULE_RE = re.compile(r"^([^:/\s]+):([^-\s]+)-(\d{10,})\.([0-9a-f]{8})$")
UA = f"rhel-fixstate/{__version__} (+https://github.com/xuxu298)"

FIELDS = ["agent", "host_os", "cve", "package", "version", "redhat_status",
          "match", "redhat_package", "advisory", "fixed_version", "severity", "wazuh_condition",
          "redhat_url"]


# ---------------------------------------------------------------- rpm versions

def _rpmvercmp(a, b):
    """Port of rpm's rpmvercmp() for one version or release string."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < lb and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if not (i < la and a[i] == "~"):
                return 1
            if not (j < lb and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if i >= la or j >= lb:
            break
        isnum = a[i].isdigit()
        kind = str.isdigit if isnum else str.isalpha
        si, sj = i, j
        while i < la and kind(a[i]):
            i += 1
        while j < lb and kind(b[j]):
            j += 1
        if sj == j:
            return 1 if isnum else -1
        x, y = a[si:i], b[sj:j]
        if isnum:
            x, y = x.lstrip("0"), y.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def split_evr(evr):
    """'1:3.0.7-27.el9' -> (1, '3.0.7', '27.el9'); no epoch -> None."""
    epoch = None
    if ":" in evr:
        e, evr = evr.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    version, _, release = evr.partition("-")
    return epoch, version, release


def compare_evr(a, b):
    """rpm order. Epochs count only when both sides state one: Wazuh and Red Hat
    do not always print the epoch for the same build."""
    ea, va, ra = split_evr(a)
    eb, vb, rb = split_evr(b)
    if ea is not None and eb is not None and ea != eb:
        return 1 if ea > eb else -1
    c = _rpmvercmp(va, vb)
    if c or not (ra and rb):
        return c
    return _rpmvercmp(ra, rb)


def split_nevr(nevr):
    """'openssl-1:3.0.7-27.el9' -> ('openssl', '1:3.0.7-27.el9')."""
    m = re.match(r"^(.+)-((?:\d+:)?[^-]+-[^-]+)$", nevr or "")
    return (m.group(1), m.group(2)) if m else (nevr or "", "")


# ---------------------------------------------------------------- Red Hat data

class RedHat:
    def __init__(self, cache_dir, ttl_hours, delay, offline, ctx):
        self.cache = Path(cache_dir)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_hours * 3600
        self.delay = delay
        self.offline = offline
        self.ctx = ctx
        self.last = 0.0
        self.calls = 0
        self.memo = {}          # one answer per CVE per run, failures included

    def get(self, cve):
        """Red Hat CVE record, None when Red Hat has no record, or raises LookupError."""
        if cve not in self.memo:
            try:
                self.memo[cve] = (True, self._get(cve))
            except LookupError as e:
                self.memo[cve] = (False, str(e))
        ok, value = self.memo[cve]
        if not ok:
            raise LookupError(value)
        return value

    def _get(self, cve):
        path = self.cache / f"{cve}.json"
        if path.exists() and (self.offline or time.time() - path.stat().st_mtime < self.ttl):
            try:
                return json.loads(path.read_text(encoding="utf-8"))["record"]
            except (ValueError, KeyError, OSError):
                pass                                    # damaged cache entry: fetch again
        if self.offline:
            raise LookupError("not in cache (--offline)")
        wait = self.delay - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        req = urllib.request.Request(RH_API.format(cve), headers={"User-Agent": UA,
                                                                  "Accept": "application/json"})
        for attempt in range(4):
            self.last = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                    record = json.loads(r.read())
                if not isinstance(record, dict):
                    raise ValueError("not a CVE record")
                break
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    record = None
                    break
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    ra = str(e.headers.get("Retry-After") or "")
                    time.sleep(min(int(ra), 300) if ra.isdigit() else 2 ** (attempt + 2))
                    continue
                raise LookupError(f"Red Hat API HTTP {e.code}") from None
            except ValueError:                          # maintenance page, truncated body
                if attempt < 3:
                    time.sleep(2 ** (attempt + 2))
                    continue
                raise LookupError("Red Hat API returned something that is not a CVE record") from None
            except (OSError, http.client.HTTPException) as e:   # URLError, timeouts, short reads
                if attempt < 3:
                    time.sleep(2 ** (attempt + 2))
                    continue
                raise LookupError(f"Red Hat API unreachable: {getattr(e, 'reason', e)}") from None
        self.calls += 1
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"record": record}), encoding="utf-8")
        tmp.replace(path)
        return record


def _major_of(cpe, product):
    m = re.search(r"enterprise_linux:(\d+)", cpe or "")
    if m:
        return m.group(1)
    m = re.fullmatch(r"Red Hat Enterprise Linux (\d+)", product or "")
    return m.group(1) if m else None


def _subpackage_of(binary, base):
    if binary == base:
        return True
    return (binary.startswith(base + "-")
            and binary[len(base) + 1:].split("-")[0] in SUBPACKAGE_SUFFIXES)


def _name_rule(binary, source):
    """True when `binary` is plausibly built from source package `source`.
    Deliberately narrow: an unusual suffix is left unmatched rather than guessed."""
    if _subpackage_of(binary, source):
        return True
    for p in SOURCE_PREFIXES:
        if source.startswith(p):
            stripped = source[len(p):]
            return (_subpackage_of(binary, stripped)
                    or _subpackage_of(binary, "python3-" + stripped))
    return False


def _fixed_row(a):
    pkg = a["package"]
    m = MODULE_RE.match(pkg)
    if m:                       # RHEL 8 module build: name:stream-version.context
        return {"kind": "module", "pkg": m.group(1), "evr": "", "stream": m.group(2),
                "advisory": a.get("advisory", ""), "state": "Fix available"}
    name, evr = split_nevr(pkg)
    return {"kind": "fixed", "pkg": name, "evr": evr, "advisory": a.get("advisory", ""),
            "state": "Fix available"}


def classify(record, major, package, version, sources):
    """Return dict with redhat_status, match, redhat_package, advisory, fixed_version.
    `sources` maps (binary name, RHEL major) -> source package name."""
    out = {"redhat_status": "", "match": "none", "redhat_package": "", "advisory": "",
           "fixed_version": ""}
    if record is None:
        out["redhat_status"] = "Not in Red Hat data"
        return out
    rows = []
    for a in record.get("affected_release") or []:
        if _major_of(a.get("cpe"), a.get("product_name")) == major and a.get("package"):
            rows.append(_fixed_row(a))
    for st in record.get("package_state") or []:
        if _major_of(st.get("cpe"), st.get("product_name")) == major:
            name = (st.get("package_name") or "").split("/")[-1]   # strip module:stream/
            rows.append({"kind": "state", "pkg": name, "evr": "", "advisory": "",
                         "state": st.get("fix_state") or "Unknown"})
    if not rows:
        out["redhat_status"] = f"No RHEL {major} entry"
        return out

    src = sources.get((package, major), sources.get((package, None)))
    levels = [("exact", lambda r: r["pkg"] == package),
              ("source-rpm", lambda r: src is not None and r["pkg"] == src)]
    if src is None:             # the naming rule only when the real source is unknown
        levels.append(("name", lambda r: _name_rule(package, r["pkg"])))
    for level, test in levels:
        hits = [r for r in rows if test(r)]
        if hits:
            # longest source name wins (openssl-fips-provider over openssl)
            best = max(len(r["pkg"]) for r in hits)
            hits = [r for r in hits if len(r["pkg"]) == best]
            out["match"] = level
            break
    else:
        states = {r["state"] for r in rows}
        # Only a status can be borrowed from other packages, never a fixed version.
        if len(states) == 1 and all(r["kind"] == "state" for r in rows):
            out.update(match="product-only", redhat_status=states.pop(),
                       redhat_package=" ".join(sorted({r["pkg"] for r in rows})))
        else:
            out["redhat_status"] = "Package not matched (" + " / ".join(sorted(states)) + ")"
        return out

    fixed = [r for r in hits if r["kind"] == "fixed" and r["evr"]]
    if fixed:
        r = fixed[0]            # the newest fixed build for this major decides
        for x in fixed[1:]:
            if compare_evr(x["evr"], r["evr"]) > 0:
                r = x
        out.update(redhat_package=r["pkg"], advisory=r["advisory"], fixed_version=r["evr"])
        if version and compare_evr(version, r["evr"]) >= 0:
            out["redhat_status"] = "Fixed version installed"
        else:
            out["redhat_status"] = "Fix available"
        return out
    other = [r for r in hits if r["kind"] in ("module", "fixed")]
    if other:
        r = other[-1]
        mod = r["kind"] == "module"
        out.update(redhat_package=r["pkg"] + (":" + r["stream"] if mod else ""),
                   advisory=r["advisory"],
                   redhat_status="Fix available (module update, version not compared)" if mod
                   else "Fix available (version not compared)")
        return out
    out["redhat_package"] = " ".join(sorted({r["pkg"] for r in hits}))
    out["redhat_status"] = " / ".join(sorted({r["state"] for r in hits}))
    return out


# ---------------------------------------------------------------- findings in

def _get(d, dotted):
    cur = d
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, dict) and dotted in cur:      # flattened export
            return cur[dotted]
        else:
            return None
    return cur


def _docs_from_json(obj):
    if isinstance(obj, dict) and isinstance(obj.get("hits"), dict):
        obj = obj["hits"].get("hits", [])
    if isinstance(obj, dict):
        obj = [obj]
    if not isinstance(obj, list):
        raise SystemExit("input: expected an _search response, a JSON list of findings, or NDJSON")
    for d in obj:
        if isinstance(d, dict):
            src = d.get("_source", d)
            yield src if isinstance(src, dict) else {}


def read_file(path):
    try:
        text = (Path(path).read_text(encoding="utf-8") if path != "-"
                else sys.stdin.buffer.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise SystemExit(f"input: {e}") from None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = None
    if obj is not None:
        yield from _docs_from_json(obj)
        return
    for no, line in enumerate(text.splitlines(), 1):             # NDJSON
        if line.strip():
            try:
                yield from _docs_from_json(json.loads(line))
            except json.JSONDecodeError:
                raise SystemExit(f"input: line {no} is not JSON (expected JSON or NDJSON)") from None


QUERY = {"size": 1000, "sort": ["_doc"],
         "_source": ["agent.name", "agent.id", "host.os.full", "host.os.name", "host.os.version",
                     "host.os.platform", "package.name", "package.version", "vulnerability.id",
                     "vulnerability.severity", "vulnerability.scanner.source",
                     "vulnerability.scanner.condition"],
         "query": {"bool": {"should": [{"term": {"host.os.platform": "rhel"}},
                                       {"match_phrase": {"host.os.name": "Red Hat Enterprise Linux"}}],
                            "minimum_should_match": 1}}}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would carry the indexer credentials elsewhere."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_indexer(url, index, user, password, ctx):
    """Read-only: GET _search with scroll, then GET _search/scroll."""
    if not url.lower().startswith("https://"):
        print("warning: the indexer URL is not https; the password is sent in clear text",
              file=sys.stderr)
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))

    def get(path, body):
        req = urllib.request.Request(url.rstrip("/") + path, method="GET",
                                     data=json.dumps(body).encode(),
                                     headers={"Authorization": auth, "User-Agent": UA,
                                              "Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise SystemExit(f"indexer: HTTP {e.code} on {path.split('?')[0]}: "
                             f"{e.read()[:300].decode(errors='replace')}") from None
        except urllib.error.URLError as e:
            raise SystemExit(f"indexer: {e.reason}") from None
        except (OSError, http.client.HTTPException, ValueError) as e:
            raise SystemExit(f"indexer: {type(e).__name__}: {e}") from None

    page = get(f"/{urllib.parse.quote(index, safe='*,-')}/_search?scroll=2m", QUERY)
    while True:
        hits = page.get("hits", {}).get("hits", [])
        if not hits:
            return
        for h in hits:
            yield h.get("_source", {})
        page = get("/_search/scroll", {"scroll": "2m", "scroll_id": page["_scroll_id"]})


def read_sources(path):
    """Lines of `rpm -qa --qf '%{NAME}\\t%{SOURCERPM}\\n'` -> {(binary, RHEL major): source}.
    The major comes from the source RPM's .elN tag, so files from RHEL 8, 9 and 10
    hosts can be concatenated without one overwriting another."""
    out = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise SystemExit(f"--rpm-sources: {e}") from None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].endswith(".src.rpm"):
            name, evr = split_nevr(parts[1][:-len(".src.rpm")])
            m = re.search(r"\.el(\d+)", evr)
            out[(parts[0], m.group(1) if m else None)] = name
    return out


def major_of_host(doc):
    v = str(_get(doc, "host.os.version") or "")
    m = re.match(r"(\d+)", v) or re.search(r"Linux (\d+)", str(_get(doc, "host.os.full") or ""))
    return m.group(1) if m else None


def is_rhel(doc):
    return (_get(doc, "host.os.platform") == "rhel"
            or "Red Hat Enterprise Linux" in str(_get(doc, "host.os.name") or _get(doc, "host.os.full") or ""))


def safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Tag Wazuh vulnerability findings on RHEL hosts with Red Hat's fix_state.",
        epilog="Indexer password: env WAZUH_INDEXER_PASSWORD, or prompted. "
               "Output: CSV on stdout (or --out), summary on stderr.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--indexer", metavar="URL", help="e.g. https://indexer:9200 (read-only GET requests)")
    src.add_argument("--input", metavar="FILE", help="exported findings: _search JSON, list or NDJSON ('-' = stdin)")
    ap.add_argument("--index", default=DEFAULT_INDEX)
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--cacert", help="CA bundle for the indexer certificate")
    ap.add_argument("--insecure", action="store_true", help="do not verify the indexer certificate")
    ap.add_argument("--rpm-sources", metavar="FILE",
                    help="output of: rpm -qa --qf '%%{NAME}\\t%%{SOURCERPM}\\n' (binary -> source names)")
    ap.add_argument("--out", metavar="CSV", help="write CSV here instead of stdout")
    ap.add_argument("--cache-dir", default=os.path.join(
        os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "rhel-fixstate"))
    ap.add_argument("--cache-hours", type=float, default=24, help="reuse Red Hat answers this long (default 24)")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between Red Hat API calls (default 1)")
    ap.add_argument("--offline", action="store_true", help="use cached Red Hat answers only")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)

    rh = RedHat(a.cache_dir, a.cache_hours, max(a.delay, 0.2), a.offline, ssl.create_default_context())
    sources = read_sources(a.rpm_sources) if a.rpm_sources else {}

    if a.indexer:
        ctx = ssl.create_default_context(cafile=a.cacert)
        if a.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        pw = os.environ.get("WAZUH_INDEXER_PASSWORD") or getpass.getpass(f"indexer password for {a.user}: ")
        # Drain the scroll before any Red Hat lookup: lookups take seconds each and
        # would let the scroll context expire between pages.
        docs = list(read_indexer(a.indexer, a.index, a.user, pw, ctx))
        print(f"read {len(docs)} findings from {a.index}", file=sys.stderr)
    else:
        docs = list(read_file(a.input))

    wrapped = not a.out and hasattr(sys.stdout, "buffer")
    out = (open(a.out, "w", newline="", encoding="utf-8") if a.out else
           io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="", line_buffering=True)
           if wrapped else sys.stdout)
    w = csv.DictWriter(out, fieldnames=FIELDS)
    w.writeheader()
    totals, cves, skipped, n = {}, set(), 0, 0
    for d in docs:
        cve = str(_get(d, "vulnerability.id") or "").strip().upper()
        if not is_rhel(d) or not CVE_RE.fullmatch(cve):
            skipped += 1
            continue
        n += 1
        major = major_of_host(d)
        pkg = str(_get(d, "package.name") or "")
        ver = str(_get(d, "package.version") or "")
        try:
            res = classify(rh.get(cve), major, pkg, ver, sources) if major else \
                {"redhat_status": "Host RHEL version unknown", "match": "none"}
        except LookupError as e:
            res = {"redhat_status": f"Lookup failed: {e}", "match": "none"}
        cves.add(cve)
        totals[res["redhat_status"]] = totals.get(res["redhat_status"], 0) + 1
        row = {"agent": _get(d, "agent.name"), "host_os": _get(d, "host.os.full"), "cve": cve,
               "package": pkg, "version": ver, "severity": _get(d, "vulnerability.severity"),
               "wazuh_condition": _get(d, "vulnerability.scanner.condition"),
               "redhat_url": RH_PAGE.format(cve.lower()), **res}
        w.writerow({k: safe(row.get(k)) for k in FIELDS})
    if a.out:
        out.close()
    elif wrapped:
        out.flush()
        out.detach()            # leave sys.stdout usable

    err = sys.stderr
    print(f"\n{n} findings on RHEL hosts, {len(cves)} distinct CVEs, "
          f"{rh.calls} fetched from the Red Hat API (rest from cache)"
          + (f", {skipped} non-RHEL or non-CVE rows skipped" if skipped else ""), file=err)
    for k, v in sorted(totals.items(), key=lambda kv: -kv[1]):
        print(f"  {v:6d}  {k}", file=err)
    return 0


if __name__ == "__main__":
    sys.exit(main())
