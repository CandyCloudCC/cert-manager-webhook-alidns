# cert-manager-webhook-alidns

面向 cert-manager 的 DNS01 webhook，使用 [Alibaba Cloud DNS 20150109 SDK v4.7.0](https://github.com/alibabacloud-go/alidns-20150109/releases/tag/v4.7.0) 直接操作阿里云云解析，帮助自动化签发 ACME 证书。

## 功能特性

- 实现 `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver` 接口，可直接被 cert-manager 作为外部 DNS01 solver 调用。
- 通过 Kubernetes Secret 引用或 `AllowAmbientCredentials` 环境变量读取 AK/SK。
- 智能解析 cert-manager 提供的 `ResolvedZone/ResolvedFQDN`，只修改所需 `_acme-challenge` TXT 记录，清理阶段仅删除匹配 value 的记录。
- 支持自定义 `endpoint`。

## 运行与调试

```bash
# 安装依赖并编译
go mod tidy
go mod download
go build -o cert-manager-webhook-alidns main.go

# 本地运行（默认 groupName 为 alidns.webhook.cert-manager.io）
GROUP_NAME=alidns.webhook.cert-manager.io ./cert-manager-webhook-alidns --help
```

构建容器镜像：

```bash
docker build -t <registry>/cert-manager-webhook-alidns:latest .
```

## 配置说明

`pkg/solver` 中的配置通过 `issuer.spec.acme.solvers[].dns01.webhook.config` 传入，支持字段：

| 字段                 | 类型                | 说明                                         |
| -------------------- | ------------------- | -------------------------------------------- |
| `AccessKeyIdRef`     | `SecretKeySelector` | 必填，指向包含 Access Key ID 的 Secret       |
| `AccessKeySecretRef` | `SecretKeySelector` | 必填，指向包含 Access Key Secret 的 Secret。 |
| `endpoint`           | `string`            | 可选，自定义 API Endpoint。                  |

## 示例：创建凭据

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: alidns-secret
  namespace: cert-manager
stringData:
  access-key-id: <YourAccessKeyId>
  access-key-secret: <YourAccessKeySecret>
```

## 示例：ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-alidns
spec:
  acme:
    email: you@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-alidns-account
    solvers:
      - dns01:
          webhook:
            groupName: alidns.webhook.cert-manager.io
            solverName: alidns
            config:
              accessKeyIdRef: access-key-id
                key: access-key-id
                name: alidns-secret
              accessKeySecretRef:
                key: access-key-secret
                name: alidns-secret
              endpoint: alidns.aliyuncs.com
```

## 部署提示

1. 部署 `Deployment`/`StatefulSet` 时设置 `GROUP_NAME` 环境变量（未设置时自动采用 `alidns.webhook.cert-manager.io`）。
2. 为 ServiceAccount 赋予访问 `secrets` 的 RBAC（`get` 权限足够）。
3. 通过 `cert-manager` 的 `webhook` solver 引用本服务对应的 `Service` 与 `Port`。
4. 生产环境建议结合 readinessProbe/livenessProbe 以及日志收集（solver 使用 `klog` 进行日志输出）。

## 进一步工作

- 根据需要增加 retries、幂等缓存或 metrics。
- 若要执行 e2e，可以针对 `pkg/solver` 编写假客户端测试或使用阿里云沙箱账号执行 `go test ./pkg/solver`。
