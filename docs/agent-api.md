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

Target must be a single IP inside DN42 address space (`172.20.0.0/14` or `fd00::/8`).

Runs fixed argv:

```text
ping -c 4 -W 3 <target>
```

## `POST /v1/lg/mtr`

Target must be a single IP inside DN42 address space (`172.20.0.0/14` or `fd00::/8`).

Runs fixed argv:

```text
mtr -r -c 5 -w <target>
```

## `POST /v1/lg/route`

Target must be an IP or CIDR prefix fully inside DN42 address space (`172.20.0.0/14` or `fd00::/8`).

Runs fixed argv:

```text
birdc show route <target>
```

Targets are validated against DN42 address ranges and never passed through a shell.
