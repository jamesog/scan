# Scan

Scan is a small web service for recording and displaying [Masscan](https://github.com/robertdavidgraham/masscan) results.

![New data](/new_data.png)
![Updated data](/updated_data.png)

## Database

Scan stores results in a SQLite database. To initialise it, run:

```
sqlite3 scan.db
CREATE TABLE scan (ip text, port integer, proto text, firstseen datetime, lastseen datetime);
CREATE TABLE users (email text);
CREATE TABLE job (id int, cidr text NOT NULL, ports text, proto text, requested_by text, submitted datetime, received datetime, count int);
CREATE TABLE traceroute (dest text UNIQUE NOT NULL, path text);
```

## Authentication & Authorization

By default the data will not be displayed unless a user has been authenticated and authorized.

Authentication is with Google OAuth2. You should create credentials for the application at https://console.cloud.google.com/apis/credentials.

* Click the down arrow next to Create credentials
* Select Web application
* Enter a name for the application (e.g. Scan)
* Add the `/auth` URI to Authorized redirect URIs
  (e.g. https://scan.example.com/auth)
* Download the JSON file containing the credentials

The JSON file should be called `client_secret.json` in the same direction as the `scan` binary.

Add the email address of each user to be permitted access to the `users` table in the database.

```
INSERT INTO users (email) VALUES ('alice@example.com');
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
