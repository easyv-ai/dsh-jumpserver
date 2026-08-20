# dsh-jumpserver

[English](./README.md)

一个 DeepSeek Harness 插件，通过对话查询 JumpServer 资产，使用 JumpServer 的 AccessKeyID/AccessKeySecret（HTTP Signature）进行鉴权。

> 项目状态：v0.1.0，最小功能集。目前只实现了资产列表查询，后续可能会添加更多 JumpServer 能力（用户、账号、授权、会话等）。

## 为什么用 dsh-jumpserver

- 按关键字搜索并列出 JumpServer 资产（主机、网络设备、数据库等）。
- 只读：本插件不会创建、修改或删除任何 JumpServer 数据。
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

- **AccessKeyID**：在 JumpServer 网页控制台的个人 API Key 列表中创建。
- **AccessKeySecret**：与上面的 AccessKeyID 配对。
- **JumpServer URL**：绝对地址，例如 `https://jumpserver.example.com`。
- **组织 ID**（可选）：多组织部署时，作为 `X-JMS-ORG` 请求头发送。

AccessKeyID/AccessKeySecret 使用 DSH 特权的本地回环凭证 RPC——只写不读，存储的值永远不会被读回或显示。URL 和组织 ID 存储在 `jumpserver` 设置命名空间中，属于非敏感字段，保存后会以明文形式回显在卡片中以便核对。

HTTP 和 HTTPS 均可直接使用——没有 TLS 证书的内部部署可以直接用 `http://` 地址，无需额外配置。请注意，纯 HTTP 会以明文方式传输签名后的请求（虽然密钥本身不会被传输），在不受信任的网络中建议优先使用 HTTPS。如需强制只使用 HTTPS，可在插件配置中关闭：

```yaml
allowInsecureHttp: false
```

凭证引用名默认是 `JUMPSERVER_ACCESS_KEY_ID` / `JUMPSERVER_ACCESS_KEY_SECRET`，可以在插件配置中通过 `akRef` / `skRef` 修改。

### JumpServer 权限建议

建议使用仅具有资产只读权限的 JumpServer 账号创建 AccessKey，避免使用超级管理员账号的密钥进行本插件的接入。

## 工具

| 工具 | 行为 |
| --- | --- |
| `jumpserver_list_assets` | 按可选的 `search` 关键字和 `limit`/`offset` 分页参数列出资产（只读）。 |

## 安全与数据边界

- AccessKeySecret 不会进入工具参数、模型消息、日志或 Git。
- 已认证的请求会拒绝 HTTP 重定向，避免签名请求被转发到其它域。
- 默认禁止非回环地址使用纯 HTTP（见 `allowInsecureHttp`）。
- 请求支持协作式取消、超时控制和响应体大小上限。
- 错误响应只暴露受长度限制的状态/详情描述。
- 资产名称、地址、备注等返回字段均视为不可信数据，不会被当作模型指令执行。

## 开发

```bash
npm ci
npm run verify
```

测试使用 Node 内置测试运行器，并对 JumpServer 响应进行了 mock。

## License

MIT
