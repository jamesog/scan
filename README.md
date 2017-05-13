# Scan

Scan is a small web service for recording and displaying [Masscan](https://github.com/robertdavidgraham/masscan) results.

## Database

Scan stores results in a SQLite database. To initialise it, run:

```
sqlite3 scan.db
CREATE TABLE scan (ip text, port integer, proto text, firstseen text, lastseen text);
CREATE TABLE users (email text);
```

## Authentication & Authorization

By default the data will not be displayed unless a user has been authenticated and authorized.

Authentication is with Google OAuth2. You should create credentials for the application at https://console.cloud.google.com/apis/credentials

* Click the down arrow next to Create credentials
* Select Web application
* Enter a name for the application (e.g. Scan)
* Add the /auth URI to Authorized redirect URIs
  (e.g. https://scan.example.com/auth)
* Download the JSON file containing the credentials

The JSON file should be called `client_secret.json` in the same direction as the `scan` binary.

Add the email address of each user to be permitted access to the `users` table in the database.

```
INSERT INTO users (email) VALUES ('alice@example.com');
```

If you want to disable authentication use the `-no-auth` flag.

## Importing data

Results are sent to /results using the POST method. The data is expected to be
a JSON array of Masscan results.

Note that Masscan generates incorrect JSON data. It looks like:

```json
{ "ip": "192.168.0.1", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] },
{ "ip": "192.168.0.1", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] },
{finished: 1}
```

That is, it is missing the surrounding `[ ]` and the last line is not valid JSON.
This must be fixed before POSTing the data.

```json
[
{ "ip": "192.168.0.1", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] },
{ "ip": "192.168.0.1", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] }
]
```

You can fix it by using `sed`:

```
sed -e '/,$/h;g;$s/,$//' -e '1i [' -e '$a ]'
```

And then send it to the server:

```
curl -H "Content-Type: application/json" -d @data.json https://scan.example.com/results
```
