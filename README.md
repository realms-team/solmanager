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
/echo
```

Any data passed in the payload of body of that request is echoed back untouched

One of the following HTTP status codes is returned:

| Code |               Meaning | Action required                                                             |
|------|-----------------------|-----------------------------------------------------------------------------|
| 200  |                    OK | Success. The body contains the same body as the request                     |
| 500  | Internal Server Error | Server error. The body MIGHT contain a description.                         |

The body of the reply contains the same contents as the body of the request.

### retrieve status

TODO

### manage data flows

TODO

### retrieve data

TODO

### start a snapshot

To start a snapshot on the manager, issue a `POST` request to the following URI 

```
/snapshot
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

TODO

