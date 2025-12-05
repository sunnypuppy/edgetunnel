# EdgeTunnel

**EdgeTunnel** 允许你在边缘计算或无服务器（Serverless）环境中运行 V2Ray，例如 Cloudflare Workers。通过利用无服务器架构，你可以创建灵活且可扩展的代理服务，适用于注重隐私的互联网访问。

## 特性

- **无服务器代理**：在边缘环境中部署 V2Ray 代理，无需传统服务器。
- **支持多种协议**：目前脚本支持 **VLESS** 和 **Trojan** 两种协议。
- **灵活与可扩展**：使用无服务器架构，提升可扩展性，减少基础设施管理。
- **注重隐私**：使用 V2Ray 协议加密互联网流量，确保隐私安全。


## 本地部署

1. 确保你已安装 [Node.js](https://nodejs.org/) 和 npm。
2. 克隆此仓库：
   ```bash
   git clone https://github.com/sunnypuppy/edgetunnel.git
   cd edgetunnel
   ```
3. 初始化 & 依赖安装
   ```bash
   npm init -y && npm install
   ```
4. 运行
   ```bash
   npx wrangler dev
   ```

## Cloudflare Workers 部署
0. 在 Cloudflare 控制台创建一个 Workers 项目。
1. 拷贝 [`/src/index.js`](https://github.com/sunnypuppy/edgetunnel/blob/master/src/index.js) 中的代码替换 workers 编辑器中内容，保存并部署。
2. 配置环境变量

    | 环境变量         | 必须    | 默认值     | 内容格式                            | 示例                                      |
    |-----------------|--------|-----------|------------------------------------|-------------------------------------------|
    | `UUID`          | 是      | 无        | 一个唯一的用户 UUID 字符串            | `d342d11e-d424-4583-b36e-524ab1f0afa4`   |
    | `SOCKS5_PROXY`  | 否      | 无        | socks5代理，用于代理访问 cf cdn 网站   | `username:passwd@127.0.0.1:8080`          |

## 使用

部署完成后，即可在代理客户端配置使用。多协议支持功能，使用了 `url.pathname` 作为协议识别，因此需要配置 `path` 路径为 `/{protocol}` 进行对应协议连接。

## 致谢

本项目部分代码参考了以下开源项目：

- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel): Running V2ray inside edge/serverless runtime.
- [ca110us/epeius](https://github.com/ca110us/epeius): 以 Serverless 的方式部署 Trojan。

感谢这些开源社区的贡献，帮助我们更好地实现功能和优化代码。

## 许可证

此项目采用 [MIT](https://github.com/sunnypuppy/edgetunnel/blob/master/LICENSE) 许可证。
