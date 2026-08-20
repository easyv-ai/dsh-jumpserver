# dsh-jumpserver

[简体中文](./README.zh-CN.md)

A DeepSeek Harness plugin for querying and managing JumpServer assets through conversation, authenticated with a JumpServer AccessKeyID/AccessKeySecret pair (HTTP Signature).

> Project status: v0.3.0. Read-only asset, user, account, permission, and session lookups are implemented, plus create/update/delete for assets behind a mandatory native user-approval prompt. Write operations on users, accounts, and permissions (password reset, permission grants, etc.) remain intentionally out of scope for now given JumpServer's role as a bastion/PAM system.

## Why dsh-jumpserver

- List and inspect JumpServer assets, users, accounts, asset-permission rules, and terminal sessions by keyword or filter.
- Create, update, and delete assets — every write requires an explicit native user-approval prompt before it runs; the model cannot bypass it.
- Never exposes secrets: account secrets/passphrases and user passwords/public keys/MFA secrets are stripped before a response reaches the model, even if the JumpServer API includes them.
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

- **JumpServer URL**: the absolute base URL, for example `https://jumpserver.example.com`.
- **Access Key**: create one from the JumpServer web console under your personal API Key list.
- **Secret Key**: paired with the Access Key above.

The Access Key/Secret Key use DSH's privileged loopback credential RPC — write-only, the stored values are never read back or displayed. The URL is stored in the `jumpserver` settings namespace as a non-secret field, so it is read back in plaintext and shown in the card for verification.

HTTP and HTTPS both work out of the box — internal deployments without TLS certificates can use an `http://` URL with no extra setup. Note that plain HTTP sends the signed request (though not the secret itself) over an unencrypted channel; prefer HTTPS over untrusted networks. To enforce HTTPS only, disable it in plugin configuration:

```yaml
allowInsecureHttp: false
```

The credential reference names default to `JUMPSERVER_ACCESS_KEY_ID` / `JUMPSERVER_ACCESS_KEY_SECRET` and can be changed with `akRef` / `skRef` in the plugin configuration.

### JumpServer permissions

Create the AccessKey under a JumpServer account that only has read access to the assets you want visible to the assistant. Avoid using a super-admin account's key for this integration.

## Tools

Read-only tools paginate with `limit` (1-100, default 20) / `offset` (default 0) where applicable.

| Tool | Behavior |
| --- | --- |
| `jumpserver_list_assets` | Lists assets with an optional `search` keyword. |
| `jumpserver_get_asset` | Gets full detail for one asset by `id`, including protocols and domain. |
| `jumpserver_list_users` | Lists users with an optional `search` keyword. Never returns passwords, public keys, or MFA secrets. |
| `jumpserver_get_user` | Gets full detail for one user by `id`. Never returns passwords, public keys, or MFA secrets. |
| `jumpserver_list_accounts` | Lists accounts (asset login credentials), optionally filtered by `asset` id or `username`. Never returns secrets or passphrases. |
| `jumpserver_get_account` | Gets full detail for one account by `id`. Never returns the secret or passphrase. |
| `jumpserver_list_permissions` | Lists asset-permission rules, optionally filtered by `userId` or `assetId`. |
| `jumpserver_list_sessions` | Lists terminal (audit) sessions, optionally filtered by `user`, `asset`, or `isFinished`. |
| `jumpserver_create_asset` | **Write.** Creates an asset (`name`, `address`, `platform` required; `comment`, `isActive` optional). Requires native user approval. |
| `jumpserver_update_asset` | **Write.** Updates an existing asset by `id`; only the fields you pass are changed. Requires native user approval. |
| `jumpserver_delete_asset` | **Write, irreversible.** Permanently deletes an asset by `id`. Requires native user approval. |

User, account, and permission write operations (create/delete users, password reset, permission grants, session termination, ticket approval) are not implemented. Given JumpServer's role as a bastion/PAM system, these affect who can log in and what they can access — a materially higher blast radius than asset records — and are deliberately deferred pending a separate decision.

### Write-tool approval

Every call to `jumpserver_create_asset`, `jumpserver_update_asset`, or `jumpserver_delete_asset` is intercepted by a `tools/pre-execute` gate (the same pattern dsh-grafana uses for `grafana_push`) and always downgraded to an explicit native approval prompt — the model cannot execute a write without it. The prompt shows the operation and the fields being changed; for updates, only the fields you pass are sent, and for deletes the asset's current name/address are read back once the delete succeeds. `jumpserver_update_asset` and `jumpserver_delete_asset` both re-check that the asset exists (an extra `GET`) before attempting the write, and fail loudly instead of silently doing nothing if it's missing.

## Security and data boundaries

- The AccessKeySecret never enters tool arguments, model messages, logs, or Git.
- Account secrets/passphrases and user passwords/public keys/MFA secrets are explicitly excluded from every tool's output, field by field — not just omitted from a generic serializer.
- Authenticated requests reject HTTP redirects to avoid forwarding signed requests to another origin.
- Non-loopback HTTP is disabled by default (see `allowInsecureHttp`).
- Requests have cooperative cancellation, timeouts, and bounded response sizes.
- Error responses expose only a bounded status/detail description.
- `id` parameters are validated as JumpServer UUIDs before being placed in a request path, preventing path injection.
- All returned fields (names, addresses, comments, usernames, etc.) are treated as untrusted data, not model instructions.

## Development

```bash
npm ci
npm run verify
```

Tests use Node's built-in test runner and mocked JumpServer responses.

## License

MIT
