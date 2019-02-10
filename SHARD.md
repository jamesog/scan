# Implementing shards

Current code is problematic: partial scan results - i.e. returning scan results that aren't part of a job, and are a lesser scan than a previous run - can invalidate "active" open services.

To implement masscan sharding we need to ensure this can't happen.

Probable implementation:

* Register IP address of each scanner and assign it a shard number or group name
* If using groups we can figure out the shard number automatically
* If we assign a shard number we can tell the scanner which shard to pass to massscan

Other improvements to make:

* Register the list of ranges to scan in the database so the scanner can pull them, rather than each scanner being configured to do (hopefully) the same thing
* Register IP exclusions too
* Try and make the exclusions IP AND port. Currently we exclude an entire IP when only one port might be a known "OK" one but others will be missed
* Perhaps the exclusions should be done in the application instead - let masscan scan them anyway to ensure that only the good port is open
* Maybe mark that the good port is open and make it visible in the UI (but hidden by default)
* Change the UI to show only active open ports by default
* Paginate output!

Also:

* Provide a systemd unit
* Provide sample scripts for running the scanner
* Add to CF scans to scan all VPSes - will need to combine with "known good" ports


CIDR ranges:

```sql
CREATE TABLE ranges (cidr text, group text);
INSERT INTO ranges (cidr, group) VALUES ('192.0.2.0/24', 'doc-prefix');
INSERT INTO ranges (cidr, group) VALUES ('173.245.58.0/23', 'CF-Anycast');
INSERT INTO ranges (cidr, group) VALUES ('173.245.58.59/32', 'CF-Exclude');
```

A scanner could be assigned ranges to include and to exclude.

Scanners:

```sql
CREATE TABLE scanners (name text, address text);
INSERT INTO scanners (name, address) VALUES ('linode-de01', '192.0.2.1');
```

Scanner group:

```sql
CREATE TABLE scanner_group (name text, scanner_name text REFERENCES scanners (name));
INSERT INTO scanner_group (name, scanner_name) VALUES ('all', 'linode-de01');
```