# Scan

Scan is a small web service for recording and displaying Masscan results.

## Database

Scan stores results in a SQLite database. To initialise it, run:

```
sqlite3 scan.db
CREATE TABLE scan (ip text, port integer, proto text, firstseen text, lastseen text);
```

## Importing data

Results are sent to /results using the POST method. The data is expected to be
a JSON array of Masscan results.

Note that Masscan generates incorrect JSON data. It looks like:

```json
{ "ip": "192.168.0.1", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] },
{ "ip": "192.168.0.1", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] },
{finished: 1}
```

That is, it is missing surround `[ ]` and the last line is not valid JSON.
This must be fixed before POSTing the data.

```json
[
{ "ip": "192.168.0.1", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] },
{ "ip": "192.168.0.1", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] }
]
```
