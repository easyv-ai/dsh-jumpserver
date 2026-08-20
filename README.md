# dsh-jumpserver

[简体中文](./README.zh-CN.md)

A DeepSeek Harness plugin for querying JumpServer assets through conversation, authenticated with a JumpServer AccessKeyID/AccessKeySecret pair (HTTP Signature).

> Project status: v0.1.0, minimal feature set. Only asset listing is implemented so far; more JumpServer capabilities (users, accounts, permissions, sessions) may follow.

## Why dsh-jumpserver

- List JumpServer assets (hosts, network devices, databases, etc.) by keyword search.
- Read-only: this plugin never creates, modifies, or deletes JumpServer data.
- Authenticate with a JumpServer AccessKeyID/AccessKeySecret pair using JumpServer's native HTTP Signature scheme (`hmac-sha256`), the same mechanism documented in JumpServer's own developer docs.
- Keep the AccessKeySecret in the local DSH credential store; it is never echoed back to the browser.

## Requirements

| Component | Supported baseline |
| --- | --- |
| Node.js | 20.11 or newer |
| DeepSeek Harness | `0.1.0-rc.6` |
| JumpServer | REST API `v1` (Access Key authentication) |

## Installation

For local development, install from the local path:

```bash
npm ci
dsh plugin --profile add link:/absolute/path/to/dsh-jumpserver
```

Once published, install a released, immutable tag whenever possible:

```bash
dsh plugin --profile add github:easyv-ai/dsh-jumpserver#v<version>
```

Install the mutable development branch only for testing:

```bash
dsh plugin --profile add github:easyv-ai/dsh-jumpserver
```

Restart the selected DSH profile after installation. On Windows, use an absolute `link:C:/path/to/dsh-jumpserver` path.

## Configuration

In DSH Web, open **Settings → Plugins → JumpServer asset lookup**.

Configure:

- **AccessKeyID**: create one from the JumpServer web console under your personal API Key list.
- **AccessKeySecret**: paired with the AccessKeyID above.
- **JumpServer URL**: the absolute base URL, for example `https://jumpserver.example.com`.
- **Organization ID** (optional): sent as the `X-JMS-ORG` header for multi-organization deployments.

The AccessKeyID/AccessKeySecret use DSH's privileged loopback credential RPC — write-only, the stored values are never read back or displayed. The URL and organization ID are stored in the `jumpserver` settings namespace as non-secret fields, so they are read back in plaintext and shown in the card for verification.

HTTP and HTTPS both work out of the box — internal deployments without TLS certificates can use an `http://` URL with no extra setup. Note that plain HTTP sends the signed request (though not the secret itself) over an unencrypted channel; prefer HTTPS over untrusted networks. To enforce HTTPS only, disable it in plugin configuration:

```yaml
allowInsecureHttp: false
```

The credential reference names default to `JUMPSERVER_ACCESS_KEY_ID` / `JUMPSERVER_ACCESS_KEY_SECRET` and can be changed with `akRef` / `skRef` in the plugin configuration.

### JumpServer permissions

Create the AccessKey under a JumpServer account that only has read access to the assets you want visible to the assistant. Avoid using a super-admin account's key for this integration.

## Tools

| Tool | Behavior |
| --- | --- |
| `jumpserver_list_assets` | Lists assets with an optional `search` keyword and `limit`/`offset` pagination (read-only). |

## Security and data boundaries

- The AccessKeySecret never enters tool arguments, model messages, logs, or Git.
- Authenticated requests reject HTTP redirects to avoid forwarding signed requests to another origin.
- Non-loopback HTTP is disabled by default (see `allowInsecureHttp`).
- Requests have cooperative cancellation, timeouts, and bounded response sizes.
- Error responses expose only a bounded status/detail description.
- Asset names, addresses, comments, and other returned fields are treated as untrusted data, not model instructions.

## Development

```bash
npm ci
npm run verify
```

Tests use Node's built-in test runner and mocked JumpServer responses.

## License

MIT
