# dsh-jumpserver

[English](./README.md)

一个 DeepSeek Harness 插件，通过对话查询并管理 JumpServer 资产，使用 JumpServer 的 AccessKeyID/AccessKeySecret（HTTP Signature）进行鉴权。

> 项目状态：v0.8.0。已实现资产、用户、账号、授权规则、会话、命令审计、用户组、命令过滤规则的只读查询，以及资产、账号、用户、资产授权规则、用户组、命令组、命令过滤规则的创建/更新/删除，以及用户的密码/MFA/SSH 密钥重置——均需经过强制的原生用户审批。考虑到 JumpServer 作为堡垒机/PAM 系统的角色，终止会话和工单审批目前有意保留不实现。

## 为什么用 dsh-jumpserver

- 按关键字或过滤条件查询 JumpServer 的资产、用户、账号、资产授权规则、终端会话、已执行命令、用户组和命令过滤规则。
- 创建、更新、删除资产、账号、用户、资产授权规则、用户组、命令组、命令过滤规则，以及重置用户的密码/MFA/SSH 密钥——每次写操作执行前都必须经过明确的原生用户审批提示，模型无法绕过。
- 拒绝删除或重置超级管理员（管理员）账号的密码，也拒绝创建"授予所有权限"式的宽泛资产授权规则或命令过滤规则——这两点都由工具自身强制执行，不只是写在文档里的约定。
- 只读查询绝不泄露敏感信息：账号的密钥/密钥密码，以及用户的密码/公钥/MFA 密钥，在返回给模型前会被逐字段剔除，即便 JumpServer API 本身返回了这些字段。
- 使用 JumpServer 官方开发文档中记录的 AccessKeyID/AccessKeySecret 签名机制（`hmac-sha256` HTTP Signature）进行鉴权。
- AccessKeySecret 保存在本地 DSH 凭证库中，永远不会被回显到浏览器。

## 环境要求

| 组件 | 支持的最低版本 |
| --- | --- |
| Node.js | 20.11 及以上 |
| DeepSeek Harness | `0.1.0-rc.6` |
| JumpServer | REST API `v1`（支持 Access Key 认证） |

## 安装

本地开发调试，从本地路径安装：

```bash
npm ci
dsh plugin --profile add link:/absolute/path/to/dsh-jumpserver
```

发布后，尽量安装已发布的、不可变的 tag 版本：

```bash
dsh plugin --profile add github:easyv-ai/dsh-jumpserver#v<version>
```

仅在测试时安装可变的开发分支：

```bash
dsh plugin --profile add github:easyv-ai/dsh-jumpserver
```

安装后需重启对应的 DSH profile。Windows 上请使用绝对路径 `link:C:/path/to/dsh-jumpserver`。

## 配置

在 DSH Web 中打开 **设置 → 插件 → JumpServer 资产查询**。

需要配置：

- **JumpServer URL**：绝对地址，例如 `https://jumpserver.example.com`。
- **Access Key**：在 JumpServer 网页控制台的个人 API Key 列表中创建。
- **Secret Key**：与上面的 Access Key 配对。

Access Key/Secret Key 使用 DSH 特权的本地回环凭证 RPC——只写不读，存储的值永远不会被读回或显示。URL 存储在 `jumpserver` 设置命名空间中，属于非敏感字段，保存后会以明文形式回显在卡片中以便核对。

HTTP 和 HTTPS 均可直接使用——没有 TLS 证书的内部部署可以直接用 `http://` 地址，无需额外配置。请注意，纯 HTTP 会以明文方式传输签名后的请求（虽然密钥本身不会被传输），在不受信任的网络中建议优先使用 HTTPS。如需强制只使用 HTTPS，可在插件配置中关闭：

```yaml
allowInsecureHttp: false
```

凭证引用名默认是 `JUMPSERVER_ACCESS_KEY_ID` / `JUMPSERVER_ACCESS_KEY_SECRET`，可以在插件配置中通过 `akRef` / `skRef` 修改。

### JumpServer 权限建议

建议使用仅具有资产只读权限的 JumpServer 账号创建 AccessKey，避免使用超级管理员账号的密钥进行本插件的接入。

## 工具

只读工具中涉及分页的接口支持 `limit`（1-100，默认 20）/ `offset`（默认 0）。

| 工具 | 行为 |
| --- | --- |
| `jumpserver_list_assets` | 按可选的 `search` 关键字列出资产。 |
| `jumpserver_get_asset` | 按 `id` 获取单个资产的完整详情，包含协议和网域信息。 |
| `jumpserver_list_users` | 按可选的 `search` 关键字列出用户。绝不返回密码、公钥或 MFA 密钥。 |
| `jumpserver_get_user` | 按 `id` 获取单个用户的完整详情。绝不返回密码、公钥或 MFA 密钥。 |
| `jumpserver_list_accounts` | 列出账号（资产上的登录凭据），可按 `asset` id 或 `username` 过滤。绝不返回密钥或密钥密码。 |
| `jumpserver_get_account` | 按 `id` 获取单个账号的完整详情。绝不返回密钥或密钥密码。 |
| `jumpserver_list_permissions` | 列出资产授权规则，可按 `userId` 或 `assetId` 过滤。 |
| `jumpserver_list_sessions` | 列出终端（审计）会话，可按 `user`、`asset` 或 `isFinished` 过滤。 |
| `jumpserver_create_asset` | **写操作。** 创建资产（必填 `name`、`address`、`platform`；可选 `comment`、`isActive`）。需要原生用户审批。 |
| `jumpserver_update_asset` | **写操作。** 按 `id` 更新已有资产；只会修改你传入的字段。需要原生用户审批。 |
| `jumpserver_delete_asset` | **写操作，不可逆。** 按 `id` 永久删除资产。需要原生用户审批。 |
| `jumpserver_create_account` | **写操作。** 创建账号（必填 `username`、`asset`；可选 `name`、`secretType`、`secret`、`passphrase`、`privileged`、`isActive`、`comment`）。需要原生用户审批，详见下方"账号密钥的处理方式"。 |
| `jumpserver_update_account` | **写操作。** 按 `id` 更新已有账号；只会修改你传入的字段，可用于轮换 `secret`/`passphrase`。需要原生用户审批。 |
| `jumpserver_delete_account` | **写操作，不可逆。** 按 `id` 永久删除账号。需要原生用户审批。 |
| `jumpserver_create_user` | **写操作。** 创建平台用户（必填 `name`、`username`、`email`；可选 `comment`、`isActive`）。不会设置初始密码——用 `jumpserver_update_user` 单独设置。需要原生用户审批。 |
| `jumpserver_delete_user` | **写操作，不可逆。** 按 `id` 永久删除用户。拒绝删除超级管理员（管理员）账号。需要原生用户审批。 |
| `jumpserver_update_user` | **写操作。** 按 `id` 更新已有用户；只会修改你传入的字段（`name`、`email`、`comment`、`isActive`）。也可以将登录密码重置为指定值（`password`）。拒绝修改超级管理员（管理员）账号的密码——其它字段仍可修改。需要原生用户审批，见下方"账号密钥的处理方式"——同样的暴露权衡适用于 `password` 值。 |
| `jumpserver_reset_user_mfa` | **写操作。** 按 `id` 解绑用户的 MFA/OTP 设备，迫使其下次登录时重新绑定。拒绝对超级管理员账号执行。需要原生用户审批。 |
| `jumpserver_reset_user_ssh_key` | **写操作。** 按 `id` 清空用户登录 JumpServer 本身所用的 SSH 公钥（不是资产账号密钥）。拒绝对超级管理员账号执行。需要原生用户审批。 |
| `jumpserver_create_permission` | **写操作。** 创建资产授权规则（必填 `name`；`assets`、`accounts` 必须是非空 UUID 数组；`users`/`userGroups` 至少提供一个且非空）。拒绝宽泛或"授予所有权限"式的匹配——不提供 `all` 或按节点匹配的选项。需要原生用户审批。 |
| `jumpserver_update_permission` | **写操作。** 按 `id` 更新已有规则；只会修改你传入的字段。传入的任何数组字段（`users`、`userGroups`、`assets`、`accounts`）都必须非空。需要原生用户审批。 |
| `jumpserver_delete_permission` | **写操作，不可逆。** 按 `id` 永久删除资产授权规则，立即撤销其授予的访问权限。需要原生用户审批。 |
| `jumpserver_list_commands` | 列出已执行的会话命令（命令审计日志），可按 `asset`、`account`、`user`、`sessionId` 或 `riskLevel` 过滤。每行的命令输出会截断到 500 字符。 |
| `jumpserver_list_user_groups` | 按可选的 `search` 关键字列出用户组。用户组本身不授予任何资产访问权限。 |
| `jumpserver_get_user_group` | 按 `id` 获取单个用户组的完整详情，包含其成员用户 id。 |
| `jumpserver_create_user_group` | **写操作。** 创建用户组（必填 `name`；可选 `users`、`comment`）。需要原生用户审批。 |
| `jumpserver_update_user_group` | **写操作。** 按 `id` 更新已有用户组；只会修改你传入的字段。若传入 `users`，必须非空。需要原生用户审批。 |
| `jumpserver_delete_user_group` | **写操作，不可逆。** 按 `id` 永久删除用户组；成员用户本身不会被删除，但引用该组的授权规则会失去对应授权。需要原生用户审批。 |
| `jumpserver_list_command_groups` | 按可选的 `search` 关键字列出命令组（命名的命令匹配规则集合）。命令组本身不生效，需要绑定到命令过滤规则上。 |
| `jumpserver_get_command_group` | 按 `id` 获取单个命令组的完整详情，包含完整的匹配内容。 |
| `jumpserver_create_command_group` | **写操作。** 创建命令组（必填 `name`、`content`；可选 `type`、`ignoreCase`、`comment`）。需要原生用户审批。 |
| `jumpserver_update_command_group` | **写操作。** 按 `id` 更新已有命令组；只会修改你传入的字段。需要原生用户审批。 |
| `jumpserver_delete_command_group` | **写操作，不可逆。** 按 `id` 永久删除命令组；绑定该组的命令过滤规则会失去对应匹配规则。需要原生用户审批。 |
| `jumpserver_list_command_filters` | 按可选的 `search` 关键字列出命令过滤规则（对匹配命令进行拒绝/告警/接受的安全规则）。 |
| `jumpserver_get_command_filter` | 按 `id` 获取单个命令过滤规则的完整详情，包含其用户/资产/账号范围和绑定的命令组。 |
| `jumpserver_create_command_filter` | **写操作。** 创建命令过滤规则（必填 `name`、`users`、`assets`、`accounts`、`commandGroupIds`，均须为非空 UUID 数组；可选 `action`——`reject`/`warning`/`accept`，默认 `reject`——`priority`、`comment`、`isActive`）。拒绝"全部用户"/"全部资产"/"全部账号"式的宽泛范围——不提供这类选项。将 `action` 设为 `accept` 会在审批提示里被标记为安全降级。需要原生用户审批。 |
| `jumpserver_update_command_filter` | **写操作。** 按 `id` 更新已有规则；只会修改你传入的字段。传入的任何范围数组字段（`users`、`assets`、`accounts`、`commandGroupIds`）都必须非空。将 `action` 改为 `accept` 会在审批提示里被标记为安全降级。需要原生用户审批。 |
| `jumpserver_delete_command_filter` | **写操作，不可逆。** 按 `id` 永久删除命令过滤规则。审批提示会展示该规则删除前的当前 `action`（在审批前实时查询），方便你在批准前看清是否正在移除一条生效中的 `reject`/`warning` 防护规则。需要原生用户审批。 |

终止会话和工单审批尚未实现，目前也没有计划实现——详见下方"范围之外"。

### 范围之外

`jumpserver_terminate_session` 曾被评估过，最终放弃：JumpServer 的 `/api/v1/terminal/tasks/kill-session/` 接口在标准 swagger 导出中没有记录请求体 schema，实际字段名只能推断、无法确认。工单审批（`/api/v1/tickets/...`）有意不实现——这会让助手替代本应由人工完成的审批步骤，而这正是 JumpServer 自身工作流所要求的。

### 写操作审批机制

对资产或账号写工具的每一次调用都会被 `tools/pre-execute` 网关拦截（与 dsh-grafana 拦截 `grafana_push` 是同一套模式），并始终降级为明确的原生审批提示——模型无法在没有审批的情况下执行写操作。审批提示会展示具体操作和将被修改的字段；更新时只会发送你传入的字段，删除成功后会读回当时的名称/地址（资产）或用户名/所属资产（账号）用于最终确认。更新和删除工具在执行写操作前都会先重新确认目标是否存在（多发一次 `GET`），如果目标已不存在会明确报错，而不是静默不做任何事。

### 账号密钥的处理方式

`jumpserver_create_account` 和 `jumpserver_update_account` 接受可选的 `secret`/`passphrase` 参数——也就是目标资产上实际的登录凭据。这是本插件"密钥绝不进入模型上下文"这一惯例的一个刻意例外：与 AccessKeySecret（只存在于 DSH 凭证库中，永远不会发给模型）不同，通过这两个工具设置的账号密钥，会经过工具调用参数才能到达 JumpServer，因此会暴露在对话内容中，以及处理该对话的模型服务商那一侧。

审批提示中永远不会显示密钥的具体值——只会提示"是否正在设置或修改密钥"这一事实——工具的返回值同样不会回显具体值。但这种脱敏止步于插件边界：如果你让助手设置一个具体的密码，那个密码在到达插件之前，都会出现在对话记录里。如果密钥值本身必须完全不经过模型上下文，建议优先使用 JumpServer 自身的自动化能力（账号推送、改密任务）来生成/轮换凭据；只有在你已明确接受这一权衡的情况下，才使用这两个工具的密钥参数。

同样的权衡也适用于 `jumpserver_update_user` 的 `password` 参数。

## 安全与数据边界

- AccessKeySecret 不会进入工具参数、模型消息、日志或 Git。
- 账号的密钥/密钥密码，以及用户的密码/公钥/MFA 密钥，会在每个**只读**工具的输出中被逐字段明确排除——而不是仅仅依赖通用序列化器的省略。（账号写工具是唯一的例外，见上方"账号密钥的处理方式"。）
- 已认证的请求会拒绝 HTTP 重定向，避免签名请求被转发到其它域。
- 默认禁止非回环地址使用纯 HTTP（见 `allowInsecureHttp`）。
- 请求支持协作式取消、超时控制和响应体大小上限。
- 错误响应只暴露受长度限制的状态/详情描述。
- `id` 参数在拼入请求路径前会校验是否为合法的 JumpServer UUID，防止路径注入。
- 所有返回字段（名称、地址、备注、用户名等）均视为不可信数据，不会被当作模型指令执行。

## 开发

```bash
npm ci
npm run verify
```

测试使用 Node 内置测试运行器，并对 JumpServer 响应进行了 mock。

## License

MIT
