# jenkins-atom-ecr-push

把一份已经保存好的容器镜像推到 Amazon ECR（或任何 Docker Registry V2 注册表），**不需要 docker 守护进程**。

原插件 `amazon-ecr` 做两件事：用 docker 构建、用 docker 推送。只有后半件是 ECR 的，前半件是
`docker-build` 原子的事。所以这个原子走注册表 HTTP API 做推送：取 token 是 SigV4 签名的
`GetAuthorizationToken`，之后就是 `HEAD/POST/PUT` 四个调用。这样在没有 docker 的 agent 上也能跑，
而正是那种 agent 最需要它。

## 用法

```bash
mvn verify    # 编译、打包到 dist/ecr-push/，再跑 src/test/java/atom/EcrPushIT.java
```

输入：

- `registry`：`123456789012.dkr.ecr.us-east-1.amazonaws.com`。region 和 account 从这个域名里读，
  region 也可以显式给；`registryEndpoint` 只改连接地址（私有端点/测试用）。
- `repository`：ECR 仓库名，可带前缀（`team/app`）。仓库不存在时这一步归 `USER` 并提示
  `aws ecr create-repository`，不会替你建。
- `tag`：默认 `latest`。写 `$BUILD_NUMBER` / `${BUILD_NUMBER}` 会被展开；展开不出来就失败，
  绝不推一个名字字面量是 `$BUILD_NUMBER` 的镜像。`extraTags` 用逗号分隔，一次推多个标签。

- `image`：镜像来源，两种形状都吃。

  - **OCI layout**：目录，或 `docker save`（20.10+）写出的 tar，里面有 `index.json` 和 `blobs/sha256/*`。
  - **老式 docker save**：tar 里是 `manifest.json` 加 `layer.tar`，这时 schema-2 清单由原子自己写。
  - 保存出来的镜像通常是 manifest **list**（每个平台一条）。注册表一个 tag 只能挂一个 manifest，
    所以先按 `platform`（如 `linux/amd64`）选一条；有多条又没给 `platform` 时直接失败并列出现有的平台。

- 凭据：`accessKey` / `secretKey` / `sessionToken`（AWS 凭据），或者直接给注册表 `password`
  （这时不再取 token，用户名为 `registryUser`，ECR 固定 `AWS`）。

出参：`digest`、`tag`/`tags`、`repository`、`registry`、`blobsUploaded`、`blobsReused`、
`imageSizeBytes`、`manifestMediaType`、`verified`。

## 不信任返回码

- 每个 blob 上传后注册表要按 URL 里的 digest 校验字节；原子也检查它回显的 digest 是否等于自己算的。
- 清单 PUT 之后，`verifyAfterWrite`（默认开）会 `HEAD` 一次 tag，把注册表**现在**解析到的摘要和自己发出去的
  摘要比对。答 201 却存了别的东西，这一步会红，归 `THIRD_PART`。
- blob 已在注册表里（`HEAD` 200）就跳过，所以重推同一个镜像不会重复上传。

## 集成测试验的是什么

`src/test/java/atom/EcrPushIT.java` 起一个假 ECR，两半都是真的。

- **token API**：拿到请求后**自己重算** SigV4（规范化请求、派生签名 key、常量时间比对），
  签名不对、region 不对、没签 x-amz-target，都会回 403；请求体里的 account 也会被断言。
- **注册表**：发一个随机 token，之后每个 `/v2/` 请求都要 Basic 认证；blob 的字节必须哈希成 URL 里的 digest；
  清单只能引用它手上真有的 blob，出错按注册表的错误码回。
  它把收到的东西存盘，所以断言可以打开推上去的镜像，读出里面的文件内容。
- 缺陷版本用来验失败路径：`--drop-manifests` 答 201 却少存一个字节，只有回读能发现；
  `--wrong-put-digest` 回一个不是它存的摘要；`--deny` 是 AccessDenied；`--expire` 是 token 过期；
  `--only-repo` 是仓库不存在；`--reject-blobs` 是拒绝上传。

## 边界

不构建镜像，那是 `docker-build` 的活。也不做 ECR 仓库管理，那属于控制面。
