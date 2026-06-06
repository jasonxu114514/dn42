# Agent API

All routes accept `Authorization: Bearer <AGENT_TOKEN>` when `AGENT_TOKEN` is configured.

## `GET /v1/status`

Runs:

```text
birdc show protocols
```

## `POST /v1/lg/ping`

Body:

```json
{"target":"172.20.0.1"}
```

Runs fixed argv:

```text
ping -c 4 -W 3 <target>
```

## `POST /v1/lg/mtr`

Runs fixed argv:

```text
mtr -r -c 5 -w <target>
```

## `POST /v1/lg/route`

Runs fixed argv:

```text
birdc show route <target>
```

Targets are validated and never passed through a shell.
