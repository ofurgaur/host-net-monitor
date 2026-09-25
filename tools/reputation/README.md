# Python threat reputation MMDB updater

Builds `mmdb/threat-reputation.mmdb` from Feodo's recommended JSON list and FireHOL
level 1. It runs on Linux and macOS with Python 3.11 or later. It does not modify
firewalls or the monitor's configuration. The monitor's current City-schema
geolocation reader cannot consume this database; reputation log enrichment and
live reload are separate integration work.

## Install and build

Run from the `host-net-monitor` project directory:

```sh
python3 -m venv .venv-reputation
.venv-reputation/bin/python -m pip install -r tools/reputation/requirements.txt
.venv-reputation/bin/python tools/reputation/update.py
```

Outputs:

- `mmdb/threat-reputation.mmdb`: custom `HostNetMonitor-Threat-Reputation` database.
- `mmdb/threat-reputation.mmdb.manifest.json`: build version, hash, counts, URLs,
  fetch confirmation times, upstream Last-Modified headers, and per-feed health.
- `mmdb/reputation-cache/`: last validated raw snapshot and download state per source.
- `*.previous`: previous published database/manifest, retained after the next build.
- `*.lock`: advisory lock file; its presence alone does not mean an update is running.

Query an IP locally, without downloading:

```sh
.venv-reputation/bin/python tools/reputation/update.py --lookup 8.8.8.8
```

An unmatched IP returns `"reputation": null`. That means not listed in the
available feeds, not that the IP is safe. This command shows the raw stored record;
check evidence `expires_at` and the manifest before using old results.

## Configure and schedule

Edit `threat-reputation.config.json`. Paths resolve relative to that file. Each
source has an enable switch, HTTPS URL, parser (`feodo_json` or `netset`), category,
refresh interval, maximum cache age, and empty-feed policy. Additional FireHOL
aggregates can use `netset`; plain IPs and IPv4/IPv6 CIDRs are accepted.

Default schedules and cache limits:

| Source | Check interval | Maximum time without successful confirmation |
| --- | --- | --- |
| Feodo recommended | 15 minutes | 1 hour |
| FireHOL level 1 GitHub mirror | 24 hours | 48 hours |

Run the updater every five minutes via a scheduler. Sources not yet due use their
validated cache; ETag/Last-Modified conditional requests avoid unnecessary body
downloads when due. `--force` checks all enabled sources immediately.

For example, a user crontab entry (replace `/absolute/project` with the real path):

```cron
*/5 * * * * /absolute/project/.venv-reputation/bin/python /absolute/project/tools/reputation/update.py --config /absolute/project/threat-reputation.config.json >> /absolute/project/reputation-updater.log 2>&1
```

Alternatively, install the included `packaging/host-net-monitor-reputation.service`
and `.timer` on Linux, or the included
`packaging/org.host-net-monitor.reputation.plist` on macOS with `StartInterval` set
to `300`. Run as the owner of
the output/cache directories; root and capture privileges are unnecessary. No
No scheduler is installed automatically. Rotate the updater log if scheduling it.

The supplied units assume the application is installed under
`/var/lib/host-net-monitor` on Linux or `/Library/Application Support/HostNetMonitor`
on macOS. Copy the updater, config, and virtual environment there, preserve the
database license files, and set ownership of the cache and `mmdb` directory to the
service account. On Linux:

```sh
sudo install -m 0644 packaging/host-net-monitor-reputation.service /etc/systemd/system/
sudo install -m 0644 packaging/host-net-monitor-reputation.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now host-net-monitor-reputation.timer
systemctl list-timers host-net-monitor-reputation.timer
```

The updater service has no special capture capability; its read-only system
protection is relaxed only for the application data directory. On macOS, install
the plist under `/Library/LaunchDaemons` and load it with:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/org.host-net-monitor.reputation.plist
```

## Evidence, overlap, and freshness

Every matched record contains `schema_version`, `database_version`, and a `matches`
array. Evidence includes source, category, original matching network, confirmation
and expiry timestamps, and feed status. Feodo also retains port, malware label,
reported status, reported first-seen, and reported last-online dates when supplied.
Source dates remain verbatim; downloading an old observation does not make it new.

`feed_status: fresh` means a successfully fetched snapshot, **not** a fresh attack
observation. `last_confirmed_in_feed` is our last successful feed fetch/304 time.
`reported_last_online` belongs to the upstream source. At the initial build, the
Feodo feed contained an older last-online observation; consult both the record and
manifest instead of interpreting a successful download as current C2 activity.

The builder splits overlapping CIDRs at boundaries and combines evidence. It never
enumerates all IP addresses in a range. An IP inside a FireHOL subnet and in Feodo
retains both matches. FireHOL level 1 includes Feodo and bogon data, so its matches
are labelled `aggregated_blocklist`, not malware, and are not independent votes.
There is no invented numerical threat score or automatic blocking.

IPv4 addresses use the MMDB IPv4 subtree inside `::/96`; explicit IPv6 prefixes
overlapping that subtree are rejected. `/0` entries are rejected. Global IPv6
networks are supported, although the default FireHOL aggregate is IPv4.

## Failures and publication

- Downloads require HTTPS, have size/time limits, retry transient failures, and
  reject malformed data rather than publishing partial parses.
- Feodo's valid empty JSON array is accepted. Empty FireHOL data is rejected by
  default. For prior lists of at least 100 entries, more than doubling or losing
  over half the entries triggers review. An explicitly allowed empty feed is an
  exception. Inspect the upstream change, then rerun with `--force
  --accept-large-change` only when appropriate.
- Failed refreshes use a validated cache until its maximum age, marking evidence
  stale. Expired sources are excluded from a new build. If every source is expired,
  the update fails and leaves the previous database in place. Its evidence still
  expires; consumers must enforce expiry. Initial builds fail if any enabled
  source has no validated snapshot. Set that source's `enabled` to false to
  deliberately build without it.
- Source removal/reconfiguration is reflected in subsequent full builds; historical
  memberships are not accumulated indefinitely.
- Each generated CIDR's first and last address are verified using the independent
  MaxMind reader before publishing. The new database is fsynced and atomically
  renamed on the same filesystem. The prior database is retained for rollback.
- Database and sidecar publication are not a two-file transaction: verify the
  sidecar's SHA-256 against the MMDB before treating them as a consistent pair.
  Existing readers must reopen the file after replacement to see new data.
- A lock prevents two instances from updating the same output simultaneously.
  Use a dedicated cache directory per configured output.

To roll back, stop scheduled updates temporarily and atomically replace the
database with a copy of its `.previous` file, along with the matching previous
manifest. Recheck the manifest hash and evidence expiry before using it.

## Tests

```sh
.venv-reputation/bin/python -m unittest discover -s tools/reputation -p 'test_*.py'
```

Tests use synthetic inputs and mocked downloads; no feed access is needed. CI
runs them on Linux and macOS. They exercise overlap merging, IPv4/IPv6 lookups,
endpoint metadata, invalid/empty responses, caching, 304 handling, expiry,
membership removal, locking, and previous-file preservation.

References: [Feodo feed documentation](https://feodotracker.abuse.ch/blocklist/),
[FireHOL mirror and update cadence](https://github.com/firehol/blocklist-ipsets),
[FireHOL level 1 composition](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset),
and [Python MMDB writer](https://pypi.org/project/mmdb-writer/).
Keep upstream source terms and attribution with any distributed derived dataset;
the writer's software license is separate from the feed data's terms.
