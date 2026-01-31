# LLM Proxy v2.0

[English](#english) | [中文](#中文)

---

## English

A lightweight LLM API proxy server with web console. **v2.0: API keys and models are configured on the server side - clients only need to specify the provider name.**

### What's New in v2.0

- **Server-side API Key storage** - Real API keys are stored on the proxy server, not exposed to clients
- **Simplified client config** - Clients only need to specify provider name (e.g., `openrouter`), no need for full model path
- **Access Token authentication** - Clients use a simple access token instead of real API keys
- **Provider switching commands** - `/proxy providers` and `/proxy provider <name>` endpoints
- **Per-provider default models** - Each provider can have a default model configured

### Quick Start

```bash
# Install dependencies
npm install

# Start server
node index.js
```

### Client Configuration (Clawdbot)

```json
{
  "models": {
    "providers": {
      "vps": {
        "baseUrl": "http://YOUR_VPS_IP:1180/v1",
        "apiKey": "llm-proxy-token",
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
| `GET /proxy/status` | Current status |

**Example:**
```bash
# List providers
curl http://localhost:1180/proxy/providers

# Switch to poe
curl http://localhost:1180/proxy/provider/poe

# Check status
curl http://localhost:1180/proxy/status
```

### Web Console

Access at `http://YOUR_IP:1180`

Features:
- Configure API keys for each provider (stored server-side)
- Set default models for each provider
- Enable/disable providers
- Set access token for client authentication
- View request logs
- Add custom providers

### API Usage

**Base URL:** `http://YOUR_IP:1180/v1`

**Model format options:**
```
# Just provider name (uses server-configured default model)
openrouter
poe

# Provider with specific model
openrouter/anthropic/claude-3.5-sonnet
poe/GPT-4o
```

---

## 中文

轻量级 LLM API 代理服务器。**v2.0: API Key 和模型在服务端配置，客户端只需指定 provider 名称。**

### v2.0 新特性

- **服务端存储 API Key** - 真实的 API Key 保存在代理服务器，不暴露给客户端
- **简化客户端配置** - 客户端只需指定 provider 名称（如 `openrouter`），无需完整 model 路径
- **Access Token 认证** - 客户端使用简单的访问令牌代替真实 API Key
- **Provider 切换命令** - `/proxy providers` 和 `/proxy provider <name>` 接口
- **Provider 默认模型** - 每个 provider 可以配置默认使用的模型

### 快速开始

```bash
# 安装依赖
npm install

# 启动服务器
node index.js
```

### 客户端配置 (Clawdbot)

```json
{
  "models": {
    "providers": {
      "vps": {
        "baseUrl": "http://你的VPS_IP:1180/v1",
        "apiKey": "llm-proxy-token",
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
| `GET /proxy/status` | 查看当前状态 |

**示例：**
```bash
# 列出 providers
curl http://localhost:1180/proxy/providers

# 切换到 poe
curl http://localhost:1180/proxy/provider/poe

# 查看状态
curl http://localhost:1180/proxy/status
```

### Web 控制台

访问 `http://你的IP:1180`

功能：
- 为每个 provider 配置 API Key（服务端存储）
- 为每个 provider 设置默认模型
- 启用/禁用 providers
- 设置客户端访问令牌
- 查看请求日志
- 添加自定义 providers

### API 使用

**Base URL:** `http://你的IP:1180/v1`

**Model 格式选项：**
```
# 只填 provider 名称（使用服务端配置的默认模型）
openrouter
poe

# Provider + 指定模型
openrouter/anthropic/claude-3.5-sonnet
poe/GPT-4o
```

---

## License

MIT
