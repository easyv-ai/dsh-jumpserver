# dsh-jumpserver

[简体中文](./README.zh-CN.md)

A DeepSeek Harness plugin for querying and managing JumpServer assets through conversation, authenticated with a JumpServer AccessKeyID/AccessKeySecret pair (HTTP Signature).

> Project status: v0.6.0. Read-only asset, user, account, permission, session, command-audit, and user-group lookups are implemented, plus create/update/delete for assets, accounts, users, asset-permission rules, and user groups, and password resets — all behind a mandatory native user-approval prompt. Session termination and ticket approval remain intentionally out of scope given JumpServer's role as a bastion/PAM system.

## Why dsh-jumpserver

- List and inspect JumpServer assets, users, accounts, asset-permission rules, terminal sessions, executed commands, and user groups by keyword or filter.
- Create, update, and delete assets, accounts, users, asset-permission rules, and user groups, and reset user passwords — every write requires an explicit native user-approval prompt before it runs; the model cannot bypass it.
- Refuses to delete or reset the password of superuser (administrator) accounts, and refuses to create asset-permission rules with broad or "grant access to everything" matching — both are enforced by the tools themselves, not just documented as a convention.
- Never exposes secrets on read: account secrets/passphrases and user passwords/public keys/MFA secrets are stripped before a response reaches the model, even if the JumpServer API includes them.
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
| `jumpserver_create_account` | **Write.** Creates an account (`username`, `asset` required; `name`, `secretType`, `secret`, `passphrase`, `privileged`, `isActive`, `comment` optional). Requires native user approval. See "Handling account secrets" below. |
| `jumpserver_update_account` | **Write.** Updates an existing account by `id`; only the fields you pass are changed. Can rotate `secret`/`passphrase`. Requires native user approval. |
| `jumpserver_delete_account` | **Write, irreversible.** Permanently deletes an account by `id`. Requires native user approval. |
| `jumpserver_create_user` | **Write.** Creates a platform user (`name`, `username`, `email` required; `comment`, `isActive` optional). Never sets a password — use `jumpserver_reset_user_password` for that. Requires native user approval. |
| `jumpserver_delete_user` | **Write, irreversible.** Permanently deletes a user by `id`. Refuses to delete superuser (administrator) accounts. Requires native user approval. |
| `jumpserver_reset_user_password` | **Write.** Resets a user's login password to a specific value (`id`, `password` required). Refuses to act on superuser accounts. Requires native user approval. See "Handling account secrets" below — the same exposure tradeoff applies to this password value. |
| `jumpserver_create_permission` | **Write.** Creates an asset-permission rule (`name` required; `assets`, `accounts` required as non-empty UUID arrays; at least one of `users`/`userGroups` required, also non-empty). Rejects broad or "grant access to everything" matching — there is no `all`/node-wide option. Requires native user approval. |
| `jumpserver_update_permission` | **Write.** Updates an existing rule by `id`; only the fields you pass are changed. Any array field you do pass (`users`, `userGroups`, `assets`, `accounts`) must be non-empty. Requires native user approval. |
| `jumpserver_delete_permission` | **Write, irreversible.** Permanently deletes an asset-permission rule by `id`, revoking the access it granted. Requires native user approval. |
| `jumpserver_list_commands` | Lists executed session commands (command audit log), optionally filtered by `asset`, `account`, `user`, `sessionId`, or `riskLevel`. Command output is truncated to 500 characters per row. |
| `jumpserver_list_user_groups` | Lists user groups with an optional `search` keyword. A group by itself grants no asset access. |
| `jumpserver_get_user_group` | Gets full detail for one user group by `id`, including its member user ids. |
| `jumpserver_create_user_group` | **Write.** Creates a user group (`name` required; `users`, `comment` optional). Requires native user approval. |
| `jumpserver_update_user_group` | **Write.** Updates an existing group by `id`; only the fields you pass are changed. If you pass `users`, it must be non-empty. Requires native user approval. |
| `jumpserver_delete_user_group` | **Write, irreversible.** Permanently deletes a user group by `id`; member users themselves are not deleted, but any permission rules referencing the group lose that grant. Requires native user approval. |

Session termination and ticket approval are not implemented, and are not currently planned — see "Out of scope" below.

### Out of scope

`jumpserver_terminate_session` was evaluated but dropped: JumpServer's `/api/v1/terminal/tasks/kill-session/` endpoint has no documented request-body schema in the standard swagger export, so the exact contract could only be inferred, not confirmed. Ticket approval (`/api/v1/tickets/...`) is intentionally not implemented — it would let the assistant substitute for a human approval step that JumpServer's own workflow requires.

### Write-tool approval

Every call to an asset or account write tool is intercepted by a `tools/pre-execute` gate (the same pattern dsh-grafana uses for `grafana_push`) and always downgraded to an explicit native approval prompt — the model cannot execute a write without it. The prompt shows the operation and the fields being changed; for updates, only the fields you pass are sent, and for deletes the current name/address (assets) or username/asset (accounts) are read back once the delete succeeds. The update and delete tools both re-check that the target exists (an extra `GET`) before attempting the write, and fail loudly instead of silently doing nothing if it's missing.

### Handling account secrets

`jumpserver_create_account` and `jumpserver_update_account` accept an optional `secret`/`passphrase` value — the actual login credential for the target asset. This is a deliberate exception to this plugin's usual rule that secrets never enter the model's context: unlike the AccessKeySecret (which lives only in the DSH credential store and is never sent to the model), an account secret set through these tools passes through the tool-call arguments to reach JumpServer, and is therefore exposed to the conversation and whatever model provider processes it.

The approval prompt never displays the literal secret value — it only states whether a secret/passphrase is being set or changed — and the tool's return value never echoes it back either. But the redaction stops at the plugin boundary: if you ask the assistant to set a specific password, that password will appear in the conversation transcript up to that point. Prefer letting JumpServer generate/rotate credentials through its own automation (account push, change-secret executions) when the value itself must stay out of the model's context; use these tools' secret parameter only when you've explicitly accepted that tradeoff.

The same tradeoff applies to `jumpserver_reset_user_password`'s `password` parameter.

## Security and data boundaries

- The AccessKeySecret never enters tool arguments, model messages, logs, or Git.
- Account secrets/passphrases and user passwords/public keys/MFA secrets are explicitly excluded from every **read** tool's output, field by field — not just omitted from a generic serializer. (Account write tools are the one exception; see "Handling account secrets" above.)
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
