This repo contains the software to run on the basestation. It:
* connects to the SmartMesh IP manager
* formats received data/notifications as sensors objects
* stores objects locally
* syncs locally-stored objects with the server
* runs a JSON API for the server to issue commands

# JSON API

The basestation offers a JSON API for the server to issue commands.

The JSON API is available over HTTP, secured using SSL.

## Security

Mutual authentication using SSL is REQUIRED. Prior to communicating between a basestation and the server:
* the certificate of the server MUST be installed on the basestation
* the certificate of the basestation MUST be installed on the server

## Base URI

The base URI of the JSON API is:

```
https://<ip address>/api/v1/
```

Only `v1` of the API is defined in this document. Future revisions of this document MIGHT define new API versions.

## API endpoints

### verify connectivity

To verify the API is up and running, one can a `GET` command to the API endpoint:

```
/echo.json
```

Any data passed in the payload of body of that request is echoed back untouched

One of the following HTTP status codes is returned:

| Code |               Meaning | Action required                                                             |
|------|-----------------------|-----------------------------------------------------------------------------|
| 200  |                    OK | Success. The body contains the same body as the request                     |
| 500  | Internal Server Error | Server error. The body MIGHT contain a description.                         |

The body of the reply contains the same contents as the body of the request.

### retrieve status

To retrieve the status of the basestation, issue a `GET` command to the API endpoint:

```
/status.json
```

No HTTP body is required. A HTTP body can be present, but will be ignored.

One of the following HTTP status codes is returned:

| Code |               Meaning | Action required                                                             |
|------|-----------------------|-----------------------------------------------------------------------------|
| 200  |                    OK | Request received successfully, snapshot is started.                         |
| 500  | Internal Server Error | Server error. The body MIGHT contain a description.                         |

The HTTP reply contains the following body:

```
{
    'software version': '1.0.2.3' 
    'uptime':           '21:01:36 up 21:49,  2 users,  load average: 0.04, 0.08, 0.05',
    'date':             'Wed Aug 12 21:02:06 UTC 2015',
    'last reboot':      'wtmp begins Wed Aug 12 21:01:33 2015',
}
```

With:
* `software version` is read from the version file of the basestation Python script.
* `uptime` is the output of the `uptime` Linux command.
* `date` is the output of the `date` Linux command.
* `last reboot` is the output of the `last reboot` Linux command.

### manage data flows

#### getting

To retrieve the status of the flows (whether on or off), issue a `GET` command to the API endpoint:

```
/flows.json
```

No HTTP body is required. A HTTP body can be present, but will be ignored.

One of the following HTTP status codes is returned:

| Code |               Meaning | Action required                                                             |
|------|-----------------------|-----------------------------------------------------------------------------|
| 200  |                    OK | Request received successfully, snapshot is started.                         |
| 500  | Internal Server Error | Server error. The body MIGHT contain a description.                         |

The HTTP reply contains the following body:

```
{
   'event':       'on',
   'log':         'off',
   'data':        'on',
   'ipData':,     'on',
   'healthReport':'on',
}
```

#### setting

To retrieve the status of the flows, issue a `POST` command to the API endpoint:

```
/flows.json
```

The HTTP body MUST be a JSON string of the following format:

```
{
   'event':       'on',
   'log':         'off',
}
```

Acceptable keys are `event`, `log`, `data`, `ipData`, `healthReport`. Acceptable values are `on` and `off`.

Flows in the request are turned on/off. Other flows are left untouched.

One of the following HTTP status codes is returned:

| Code |               Meaning | Action required                                                             |
|------|-----------------------|-----------------------------------------------------------------------------|
| 200  |                    OK | Request received successfully, snapshot is started.                         |
| 400  |           Bad Request | The request is either no JSON, or doesn't contain the right keys/values     |
| 500  | Internal Server Error | Server error. The body MIGHT contain a description.                         |

The HTTP reply contains the following body. This is the same reply body as the `GET` command:

```
{
   'event':       'on',
   'log':         'off',
   'data':        'on',
   'ipData':,     'on',
   'healthReport':'on',
}
```

### retrieve data

TODO

### start a snapshot

To start a snapshot on the manager, issue a `POST` request to the following URI 

```
/snapshot.json
```

No HTTP body is required. A HTTP body can be present, but will be ignored.

One of the following HTTP status codes is returned:

| Code |               Meaning | Action required                                                             |
|------|-----------------------|-----------------------------------------------------------------------------|
| 200  |                    OK | Request received successfully, snapshot is started.                         |
| 202  |                    OK | Snapshot already ongoing, no new snapshot is started.                       |
| 500  | Internal Server Error | Server error. The body MIGHT contain a description.                         |

No HTTP body is present in the reply.

### issue a raw SmartMesh IP API command

To issue an arbitrary command on the SmartMesh IP manager [Serial API](http://www.linear.com/docs/41883), issue a `POST` command to the following URI:

```
/smartmeshipapi.json
```

The HTTP body MUST be a JSON string of the following format:

```
{
TODO
}
```

One of the following HTTP status codes is returned:

| Code |               Meaning | Action required                                                             |
|------|-----------------------|-----------------------------------------------------------------------------|
| 200  |                    OK | Request received, command issues, body contains reply.                      |
| 400  |           Bad Request | Something is wrong with the request.                                        |
| 500  | Internal Server Error | Server error. The body MIGHT contain a description.                         |

The HTTP reply contains the reply from SmartMesh IP manager, encoded as a JSON string.

```
TODO
```
