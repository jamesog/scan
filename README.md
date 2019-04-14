# Scan

Scan is a small web service for recording and displaying [Masscan](https://github.com/robertdavidgraham/masscan) results.

![New data](/new_data.png)
![Updated data](/updated_data.png)

## Building and Installation

As of v0.8.1 Scan uses Go modules and requires Go 1.11 or newer to build.

Precompiled binaries for Linux on x86-64 are available on the GitHub releases page.

Both build and runtime require the SQLite libraries installed.

For a Debian system:

```
sudo apt-get install sqlite3
```

Or macOS:

```
brew install sqlite
```

## Database

Scan stores results in a SQLite database. The database is automatically created and maintained at startup.

The `-data.dir` flag (defaults to current directory) tells Scan where to store the database file.

## TLS

Scan can automatically obtain a TLS certificate for HTTPS using Let's Encrypt.

When the `-tls` flag is set and a client connects to the HTTPS port, Scan will attempt to automatically obtain a certificate for the hostname being connected to. A DNS hostname must be set up for this to work as Let's Encrypt uses Domain Validation - it needs to connect to the hostname on the HTTP port.

Optionally, you can restrict certificates to a single hostname using the `-tls.hostname` flag.

## Authentication & Authorization

By default the data will not be displayed unless a user has been authenticated and authorized.

Authentication is with Google OAuth2. You should create credentials for the application at https://console.cloud.google.com/apis/credentials.

* Click the down arrow next to Create credentials
* Select Web application
* Enter a name for the application (e.g. Scan)
* Add the `/auth` URI to Authorized redirect URIs
  (e.g. https://scan.example.com/auth)
* Download the JSON file containing the credentials

Scan will look for the credentials file called `client_secret.json` in the data directory (`-data.dir` flag) by default. The data directory defaults to the current directory. The credentials file path can be changed with the `-credentials` flag. If a relative path is specified it's assumed the file is in the data directory.

Users can be managed at the `/admin` URI.

If you want to authorise users by a G Suite group you must enable the
[Admin SDK](https://console.cloud.google.com/apis/api/admin.googleapis.com/overview) on the project
and add the group address to the `groups` table:

```
INSERT INTO groups (group_name) VALUES ('scan-users@example.com');
```

If you want to disable authentication use the `-no-auth` flag.

## Importing data

Results are sent to `/results` using the `POST` method. The data is expected to be
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

When automating this you should ensure you don't send empty data to the server.
If the output file is empty you should send an empty JSON array (`[]`).

## Jobs

Jobs allow you to request nodes to perform specific scans, possibly in addition
to the scans they usually do.

Once job data has been submitted, the job list will show a count of how many
ports were found.

![Job list](/jobs.png)

Nodes fetch the job list from `/jobs`. This is a JSON document of the form:

```json
[
  {
    "id": 1,
    "cidr": "192.0.2.0/24",
    "ports": "1-1024",
    "proto": "tcp"
  }
]
```

Job data is submitted similar to normal results, but using the `PUT` method
and appending the job ID to the URI, e.g.

```
curl -H "Content-Type: application/json" -X PUT -d @data.json https://scan.example.com/results/1
```

## Traceroutes

To aid with network debugging after finding open ports, you can submit a
traceroute for the IP. This should be `POST`ed to `/traceroute` as multipart
form data, e.g.

```
curl -F dest=192.0.2.1 -F traceroute=@traceroute.txt https://scan.example.com/traceroute
```

## Metrics

Prometheus metrics are available to allow you to monitor and alert on Scan results. By default it listens on `localhost:3000`.

Listening on a separate port from the main web server is deliberate - if you have authentication enabled the metrics data could leak information. If you configure metrics to listen on a public interface you should use IP ACLs to control access.

TLS can be enabled on the metrics server (`-metrics.tls`) if TLS is also enabled for the main server.
