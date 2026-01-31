# Clawd Proxy

[English](#english) | [中文](#中文)

---

## English

A lightweight LLM API proxy server with web console. API keys and models are configured on the server side - clients only need an access token.

### Features

- **Server-side API Key storage** - Real API keys are stored on the proxy server, not exposed to clients
- **Simplified client config** - Clients only need to specify provider name (e.g., `openrouter`), no need for full model path
- **Access Token authentication** - Clients use a simple access token instead of real API keys
- **Provider switching commands** - `/proxy/providers` and `/proxy/provider/<name>` endpoints
- **Per-provider default models** - Each provider can have a default model configured
- **SSL/HTTPS support** - Upload certificates or specify local paths
- **Bilingual Web UI** - English and Chinese interface

### Installation

```bash
# Install globally
npm install -g clawd-proxy

# Start server
clawd-proxy
```

### Client Configuration (Clawdbot)

```json
{
  "models": {
    "providers": {
      "vps": {
        "baseUrl": "http://YOUR_VPS_IP:1180/v1",
        "apiKey": "your-access-token",
        "api": "openai-completions",
        "models": [
          { "id": "openrouter", "name": "openrouter" }
        ]
      }
    }
  },
  "agents": {
    "model": {
      "primary": "vps/openrouter"
    }
  }
}
```

That's it! The real API key and default model are configured in the proxy's web console.

### Command Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /proxy/providers` | List all available providers |
| `GET /proxy/provider/<name>` | Switch to a provider |
| `GET /proxy/status` | Current status with details |
| `GET /health` | Health check |

### Web Console

Access at `http://YOUR_IP:1180`

Features:
- Configure API keys for each provider (stored server-side)
- Set default models for each provider
- Enable/disable providers
- Set access token for client authentication
- View request logs
- Add custom providers
- SSL/HTTPS configuration
- Change server port

---

## 中文

轻量级 LLM API 代理服务器，带 Web 控制台。API Key 和模型在服务端配置，客户端只需访问令牌。

### 特性

- **服务端存储 API Key** - 真实的 API Key 保存在代理服务器，不暴露给客户端
- **简化客户端配置** - 客户端只需指定 provider 名称（如 `openrouter`），无需完整 model 路径
- **Access Token 认证** - 客户端使用简单的访问令牌代替真实 API Key
- **Provider 切换命令** - `/proxy/providers` 和 `/proxy/provider/<name>` 接口
- **Provider 默认模型** - 每个 provider 可以配置默认使用的模型
- **SSL/HTTPS 支持** - 上传证书或指定本地路径
- **中英文双语界面**

### 安装

```bash
# 全局安装
npm install -g clawd-proxy

# 启动服务器
clawd-proxy
```

### 客户端配置 (Clawdbot)

```json
{
  "models": {
    "providers": {
      "vps": {
        "baseUrl": "http://你的VPS_IP:1180/v1",
        "apiKey": "你的访问令牌",
        "api": "openai-completions",
        "models": [
          { "id": "openrouter", "name": "openrouter" }
        ]
      }
    }
  },
  "agents": {
    "model": {
      "primary": "vps/openrouter"
    }
  }
}
```

就这么简单！真实的 API Key 和默认模型在代理服务器的 Web 控制台配置。

### 命令接口

| 端点 | 说明 |
|------|------|
| `GET /proxy/providers` | 列出所有可用的 providers |
| `GET /proxy/provider/<name>` | 切换到指定 provider |
| `GET /proxy/status` | 当前状态详情 |
| `GET /health` | 健康检查 |

### Web 控制台

访问 `http://你的IP:1180`

功能：
- 为每个 provider 配置 API Key（服务端存储）
- 为每个 provider 设置默认模型
- 启用/禁用 providers
- 设置客户端访问令牌
- 查看请求日志
- 添加自定义 providers
- SSL/HTTPS 配置
- 修改服务器端口

---

## License

MIT
