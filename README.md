# rhel-fixstate

Tag Wazuh vulnerability findings on RHEL hosts with Red Hat's own status for that CVE, so the *Will not fix* and *Fix deferred* rows can be told apart from the ones with an advisory you can install.

Wazuh Vulnerability Detection reports a CVE whenever the installed package falls in the affected range. Red Hat publishes, per CVE and per RHEL major version, either the advisory that fixes it (`affected_release`) or why there is none (`package_state.fix_state`: *Will not fix*, *Fix deferred*, *Affected*, *Out of support scope*, …). This script joins the two.

- **Read-only.** It reads `wazuh-states-vulnerabilities-*` with GET requests (`_search` + scroll) or an exported JSON file. It writes nothing to the indexer and never follows a redirect with your credentials.
- **One file, Python 3.6+ standard library** (runs on RHEL 8 platform-python).
- **Polite to Red Hat.** One request per distinct CVE per run, at most one per second by default; answers cached on disk for 24 h.

## Run

```sh
# from the indexer (password from WAZUH_INDEXER_PASSWORD, or prompted)
python3 rhel-fixstate.py --indexer https://indexer:9200 --user admin \
    --cacert root-ca.pem --out rhel-fixstate.csv

# or from an export (an _search response, a JSON list, or NDJSON)
python3 rhel-fixstate.py --input findings.json --out rhel-fixstate.csv
```

A read-only indexer user needs `read` on `wazuh-states-vulnerabilities-*`. A summary goes to stderr. On our lab (Wazuh 4.14.8, three RHEL agents) it read:

```
1690 findings on RHEL hosts, 591 distinct CVEs
     920  Fix deferred
     386  Affected
     360  Fix available
      20  Will not fix
       4  Out of support scope
```

All 360 *Fix available* rows were on the one host left at RHEL 9.4. The two fully updated hosts (9.8 and 10.2) had 861 findings between them and none with a Red Hat fix to install.

## Output columns

`agent, host_os, cve, package, version, redhat_status, match, redhat_package, advisory, fixed_version, severity, wazuh_condition, redhat_url`

`redhat_status`:

| value | meaning |
|---|---|
| Fix available | Red Hat shipped a fix for this RHEL major (`advisory`, `fixed_version`) and the installed version is older |
| Fixed version installed | the installed version is at or above Red Hat's fixed build |
| Fix available (module update, version not compared) | the fix ships in the installed module stream (`redhat_package` = `module:stream`); check the advisory |
| Module stream not matched | RHEL 8/9 module: Red Hat answers per stream, and none of its streams could be tied to the installed build. `redhat_package` lists the streams Red Hat covers (`module:stream` or `module:stream/package`) and `advisory` their advisories; check `dnf module list --enabled` and pick yours. Never another stream's answer |
| Will not fix, Fix deferred, Affected, Out of support scope, Not affected, … | Red Hat's `fix_state` for this RHEL major; no fix shipped. Several values joined with ` / ` when the matched rows differ |
| No RHEL N entry | Red Hat has rows for this CVE, none for the host's major version |
| Not in Red Hat data | Red Hat has no record of the CVE |
| Package not matched (…) | the package could not be tied to a Red Hat row, and the rows for this major disagree or include a fix; the statuses present are listed |
| Lookup failed: … | the Red Hat API could not be read for this CVE |

## How packages are matched (`match` column)

Red Hat names **source** packages (`rust-sequoia-sq`), Wazuh names **binary** packages (`sequoia-sq`). Every row says how they were joined:

| match | how |
|---|---|
| exact | same name |
| source-rpm | through the source RPM you supplied with `--rpm-sources` |
| name | naming rule, deliberately narrow: a common sub-package suffix (`openssl-libs`, `vim-minimal`) or an ecosystem prefix (`sequoia-sq` ← `rust-sequoia-sq`). Used only when `--rpm-sources` does not know the package |
| product-only | no name matched; every Red Hat row for that major has the same `fix_state` and none is a fix, so that status is reported. `redhat_package` shows which packages it came from |
| none | not matched; `redhat_status` says why |

The naming rule leaves unusual names unmatched rather than guessing (`libgcc` ← `gcc`, `libcap-ng` vs `libcap`). For exact joins, give it the binary→source map. Files from RHEL 8, 9 and 10 hosts can be concatenated: the `.elN` tag of each source RPM keeps them apart.

```sh
rpm -qa --qf '%{NAME}\t%{SOURCERPM}\n' > rpm-sources-$(hostname).txt   # on each image or host
cat rpm-sources-*.txt > rpm-sources.txt
python3 rhel-fixstate.py --input findings.json --rpm-sources rpm-sources.txt
```

On our lab, with the map every finding matched (`exact` or `source-rpm`). Without it, 209 of 1690 were left unmatched, and on the 1010 rows matched by `name` or `product-only` the status agreed with the source-RPM answer in every case.

## Limits

- RHEL only. Ubuntu, Debian and other distributions publish their status differently and are not covered.
- Only the main RHEL stream (`enterprise_linux:<major>`). EUS/AUS/E4S advisories are not considered, so a host on an EUS stream may show *Fix available* for a fix that only exists on the main stream, or miss an EUS-only fix.
- Red Hat's status is per source package and per major version, not per minor release or per host configuration. *Will not fix* means Red Hat will not ship a fix; whether the finding matters on your host is still your call.
- Version comparison follows rpm's ordering. When only one side states an epoch, epochs are ignored. Module builds are not version-compared. The stream is taken from the installed version's major.minor, else its major (ruby 2.5.9 → ruby:2.5, nodejs 18.19.1 → nodejs:18), only when the package name itself matched; a binary matched through its source rpm (rubygems, npm) carries its own version, so it gets *Module stream not matched*. A module build (`.module+el` in the release) is never checked against a non-modular fix, and a non-modular build is checked only against the non-modular rows.

## Licence

Apache-2.0. Not affiliated with Red Hat or Wazuh. Red Hat data © Red Hat, from the [Red Hat Security Data API](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html/red_hat_security_data_api/index).
