# dsh-jumpserver

[English](./README.md)

一个 DeepSeek Harness 插件，通过对话查询并管理 JumpServer 资产，使用 JumpServer 的 AccessKeyID/AccessKeySecret（HTTP Signature）进行鉴权。

> 项目状态：v0.3.0。已实现资产、用户、账号、授权规则、会话的只读查询，以及资产的创建/更新/删除（均需经过强制的原生用户审批）。用户、账号、授权规则相关的写操作（重置密码、授权变更等），考虑到 JumpServer 作为堡垒机/PAM 系统的角色，目前有意保留不实现。

## 为什么用 dsh-jumpserver

- 按关键字或过滤条件查询 JumpServer 的资产、用户、账号、资产授权规则和终端会话。
- 创建、更新、删除资产——每次写操作执行前都必须经过明确的原生用户审批提示，模型无法绕过。
- 绝不泄露敏感信息：账号的密钥/密钥密码，以及用户的密码/公钥/MFA 密钥，在返回给模型前会被逐字段剔除，即便 JumpServer API 本身返回了这些字段。
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

用户、账号、授权规则相关的写操作（创建/删除用户、重置密码、授权变更、终止会话、工单审批）尚未实现。考虑到 JumpServer 作为堡垒机/PAM 系统的角色，这些操作直接影响谁能登录、谁能访问什么资产——影响范围明显高于资产记录本身——因此有意延后，留待单独决策。

### 写操作审批机制

对 `jumpserver_create_asset`、`jumpserver_update_asset`、`jumpserver_delete_asset` 的每一次调用都会被 `tools/pre-execute` 网关拦截（与 dsh-grafana 拦截 `grafana_push` 是同一套模式），并始终降级为明确的原生审批提示——模型无法在没有审批的情况下执行写操作。审批提示会展示具体操作和将被修改的字段；更新时只会发送你传入的字段，删除成功后会读回资产当时的名称/地址用于最终确认。`jumpserver_update_asset` 和 `jumpserver_delete_asset` 在执行写操作前都会先重新确认资产是否存在（多发一次 `GET`），如果资产已不存在会明确报错，而不是静默不做任何事。

## 安全与数据边界

- AccessKeySecret 不会进入工具参数、模型消息、日志或 Git。
- 账号的密钥/密钥密码，以及用户的密码/公钥/MFA 密钥，会在每个工具的输出中被逐字段明确排除——而不是仅仅依赖通用序列化器的省略。
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
