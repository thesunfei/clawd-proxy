#!/usr/bin/env node
/**
 * LLM Proxy Server v2.1
 * - 代理 OpenRouter / Poe / 自定义大模型 API
 * - Web 控制台管理
 * - 服务端配置 API Key 和 Model，客户端只需指定 provider
 * - 支持 /proxy providers 和 /proxy provider <name> 命令
 * - 支持自定义端口和 HTTPS
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const multer = require('multer');

const app = express();
const DATA_DIR = path.join(__dirname, '.data');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const LOG_FILE = path.join(DATA_DIR, 'requests.log');
const SSL_DIR = path.join(DATA_DIR, 'ssl');

// 文件上传配置
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 1024 * 1024 } // 1MB
});

// 日志函数
function log(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] [${level}] ${message} ${Object.keys(data).length ? JSON.stringify(data) : ''}`;
    console.log(logLine);
    
    try {
        fs.appendFileSync(LOG_FILE, logLine + '\n');
        const stats = fs.statSync(LOG_FILE);
        if (stats.size > 1024 * 1024) {
            const content = fs.readFileSync(LOG_FILE, 'utf8');
            fs.writeFileSync(LOG_FILE, content.slice(-512 * 1024));
        }
    } catch (e) {}
}

// 请求日志存储（最近100条）
const requestLogs = [];
function addRequestLog(entry) {
    requestLogs.unshift({ ...entry, time: new Date().toISOString() });
    if (requestLogs.length > 100) requestLogs.pop();
}

// 确保数据目录存在
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(SSL_DIR)) {
    fs.mkdirSync(SSL_DIR, { recursive: true });
}

// 默认配置 - v2.1 新增端口和 SSL 配置
const DEFAULT_CONFIG = {
    password: '33333333',
    sessionSecret: crypto.randomBytes(32).toString('hex'),
    // 访问令牌（客户端用这个代替真实 API Key）
    accessToken: 'llm-proxy-token',
    // 服务器配置
    port: 1180,
    ssl: {
        enabled: false,
        cert: '',  // 证书文件名
        key: ''    // 私钥文件名
    },
    // 当前激活的 provider（全局默认）
    activeProvider: 'openrouter',
    // model 历史记录
    modelHistory: [],
    providers: {
        openrouter: {
            name: 'OpenRouter',
            enabled: true,
            baseUrl: 'https://openrouter.ai/api/v1',
            apiKey: '',  // 服务端配置真实 API Key
            defaultModel: 'google/gemma-3-27b-it:free',  // 默认模型
            description: '支持多种模型的统一 API'
        },
        poe: {
            name: 'Poe',
            enabled: true,
            baseUrl: 'https://api.poe.com/v1',
            apiKey: '',
            defaultModel: 'GPT-4o',
            description: 'Poe API (OpenAI 兼容)'
        }
    },
    customProviders: []
};

// 加载配置
function loadConfig() {
    try {
        if (fs.existsSync(CONFIG_FILE)) {
            const data = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
            // 合并默认配置，确保新字段存在
            const merged = { ...DEFAULT_CONFIG, ...data };
            // 确保 providers 有新字段
            for (const [key, defaultProvider] of Object.entries(DEFAULT_CONFIG.providers)) {
                if (merged.providers[key]) {
                    merged.providers[key] = { ...defaultProvider, ...merged.providers[key] };
                }
            }
            // 确保 modelHistory 存在
            if (!merged.modelHistory) merged.modelHistory = [];
            // 确保 ssl 配置存在
            if (!merged.ssl) merged.ssl = { enabled: false, cert: '', key: '' };
            if (!merged.port) merged.port = 1180;
            return merged;
        }
    } catch (e) {
        console.error('加载配置失败:', e.message);
    }
    return { ...DEFAULT_CONFIG };
}

// 保存配置
function saveConfig(config) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// 添加 model 到历史记录
function addModelToHistory(model) {
    if (!model || model.trim() === '') return;
    model = model.trim();
    // 移除已存在的（去重）
    config.modelHistory = config.modelHistory.filter(m => m !== model);
    // 添加到开头
    config.modelHistory.unshift(model);
    // 最多保留 50 条
    if (config.modelHistory.length > 50) {
        config.modelHistory = config.modelHistory.slice(0, 50);
    }
    saveConfig(config);
}

let config = loadConfig();

// 中间件
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session 验证
function getSessionToken() {
    return crypto.createHash('sha256').update(config.password + config.sessionSecret).digest('hex').slice(0, 32);
}

function requireAuth(req, res, next) {
    const token = req.cookies?.llm_proxy_session;
    if (token === getSessionToken()) {
        return next();
    }
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: '未登录' });
    }
    return res.redirect('/login');
}

// ============ 命令接口 (给 Clawdbot 用) ============

// GET /proxy/providers - 列出所有 providers
app.get('/proxy/providers', (req, res) => {
    const providers = [];
    
    // 内置 providers
    for (const [id, p] of Object.entries(config.providers)) {
        if (p.enabled) {
            providers.push({
                id,
                name: p.name,
                model: p.defaultModel || '(未配置)',
                active: id === config.activeProvider,
                hasApiKey: !!p.apiKey
            });
        }
    }
    
    // 自定义 providers
    for (const p of config.customProviders) {
        if (p.enabled) {
            providers.push({
                id: p.id,
                name: p.name,
                model: p.defaultModel || '(未配置)',
                active: p.id === config.activeProvider,
                hasApiKey: !!p.apiKey
            });
        }
    }
    
    res.json({
        activeProvider: config.activeProvider,
        providers
    });
});

// GET /proxy/provider/:name - 切换到指定 provider
app.get('/proxy/provider/:name', (req, res) => {
    const name = req.params.name.toLowerCase();
    
    // 检查是否存在
    const builtIn = config.providers[name];
    const custom = config.customProviders.find(p => p.id.toLowerCase() === name);
    
    if (!builtIn && !custom) {
        return res.status(404).json({
            success: false,
            error: `Provider "${name}" not found`,
            available: [
                ...Object.keys(config.providers).filter(k => config.providers[k].enabled),
                ...config.customProviders.filter(p => p.enabled).map(p => p.id)
            ]
        });
    }
    
    const provider = builtIn || custom;
    const providerId = builtIn ? name : custom.id;
    
    if (!provider.enabled) {
        return res.status(400).json({
            success: false,
            error: `Provider "${providerId}" is disabled`
        });
    }
    
    // 切换
    config.activeProvider = providerId;
    saveConfig(config);
    
    res.json({
        success: true,
        message: `Switched to ${provider.name}`,
        provider: {
            id: providerId,
            name: provider.name,
            model: provider.defaultModel,
            hasApiKey: !!provider.apiKey
        }
    });
});

// GET /proxy/status - 当前状态
app.get('/proxy/status', (req, res) => {
    const provider = config.providers[config.activeProvider] 
        || config.customProviders.find(p => p.id === config.activeProvider);
    
    res.json({
        activeProvider: config.activeProvider,
        providerName: provider?.name,
        model: provider?.defaultModel,
        hasApiKey: !!provider?.apiKey,
        baseUrl: provider?.baseUrl
    });
});

// ============ 登录和管理面板 ============

app.get('/login', (req, res) => {
    res.type('html').send(getLoginHTML());
});

app.post('/login', (req, res) => {
    const { password } = req.body;
    if (password === config.password) {
        res.cookie('llm_proxy_session', getSessionToken(), { httpOnly: true, sameSite: 'strict' });
        return res.json({ success: true });
    }
    res.status(401).json({ error: '密码错误' });
});

app.get('/logout', (req, res) => {
    res.clearCookie('llm_proxy_session');
    res.redirect('/login');
});

app.get('/', requireAuth, (req, res) => {
    res.type('html').send(getAdminHTML());
});

// API: 获取配置
app.get('/api/config', requireAuth, (req, res) => {
    const safeConfig = { ...config };
    delete safeConfig.sessionSecret;
    // 隐藏 API Key 的完整值，只显示是否配置
    const maskedConfig = JSON.parse(JSON.stringify(safeConfig));
    for (const [key, provider] of Object.entries(maskedConfig.providers)) {
        if (provider.apiKey) {
            provider.apiKeyMasked = provider.apiKey.slice(0, 8) + '...' + provider.apiKey.slice(-4);
        }
    }
    for (const provider of maskedConfig.customProviders) {
        if (provider.apiKey) {
            provider.apiKeyMasked = provider.apiKey.slice(0, 8) + '...' + provider.apiKey.slice(-4);
        }
    }
    res.json(maskedConfig);
});

// API: 更新密码
app.post('/api/password', requireAuth, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (oldPassword !== config.password) {
        return res.status(400).json({ error: '原密码错误' });
    }
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: '新密码至少6位' });
    }
    config.password = newPassword;
    saveConfig(config);
    res.clearCookie('llm_proxy_session');
    res.json({ success: true, message: '密码已更新，请重新登录' });
});

// API: 更新 access token
app.post('/api/access-token', requireAuth, (req, res) => {
    const { accessToken } = req.body;
    if (!accessToken || accessToken.length < 8) {
        return res.status(400).json({ error: 'Access Token 至少8位' });
    }
    config.accessToken = accessToken;
    saveConfig(config);
    res.json({ success: true });
});

// API: 更新端口
app.post('/api/port', requireAuth, (req, res) => {
    const { port } = req.body;
    const portNum = parseInt(port);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        return res.status(400).json({ error: '端口号无效 (1-65535)' });
    }
    config.port = portNum;
    saveConfig(config);
    res.json({ success: true, message: '端口已更新，重启服务后生效', needRestart: true });
});

// API: 上传 SSL 证书
app.post('/api/ssl/upload', requireAuth, upload.fields([
    { name: 'cert', maxCount: 1 },
    { name: 'key', maxCount: 1 }
]), (req, res) => {
    try {
        if (req.files?.cert?.[0]) {
            const certFile = path.join(SSL_DIR, 'server.crt');
            fs.writeFileSync(certFile, req.files.cert[0].buffer);
            config.ssl.cert = 'server.crt';
        }
        if (req.files?.key?.[0]) {
            const keyFile = path.join(SSL_DIR, 'server.key');
            fs.writeFileSync(keyFile, req.files.key[0].buffer);
            config.ssl.key = 'server.key';
        }
        saveConfig(config);
        res.json({ success: true, message: 'SSL 证书已上传' });
    } catch (e) {
        res.status(500).json({ error: '上传失败: ' + e.message });
    }
});

// API: 启用/禁用 SSL
app.post('/api/ssl/toggle', requireAuth, (req, res) => {
    const { enabled } = req.body;
    
    if (enabled) {
        // 检查证书文件是否存在（支持本地路径或上传的文件）
        let certPath = config.ssl.certPath || path.join(SSL_DIR, config.ssl.cert || 'server.crt');
        let keyPath = config.ssl.keyPath || path.join(SSL_DIR, config.ssl.key || 'server.key');
        
        if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
            return res.status(400).json({ error: '请先上传 SSL 证书和私钥，或指定本地路径' });
        }
    }
    
    config.ssl.enabled = enabled;
    saveConfig(config);
    res.json({ success: true, message: enabled ? 'SSL 已启用，重启服务后生效' : 'SSL 已禁用，重启服务后生效', needRestart: true });
});

// API: 设置 SSL 本地路径
app.post('/api/ssl/path', requireAuth, (req, res) => {
    const { certPath, keyPath } = req.body;
    
    // 验证路径是否存在
    if (certPath) {
        if (!fs.existsSync(certPath)) {
            return res.status(400).json({ error: `证书文件不存在: ${certPath}` });
        }
        config.ssl.certPath = certPath;
    }
    
    if (keyPath) {
        if (!fs.existsSync(keyPath)) {
            return res.status(400).json({ error: `私钥文件不存在: ${keyPath}` });
        }
        config.ssl.keyPath = keyPath;
    }
    
    saveConfig(config);
    res.json({ success: true, message: 'SSL 路径已保存' });
});

// API: 清除 SSL 本地路径（改用上传的文件）
app.post('/api/ssl/clear-path', requireAuth, (req, res) => {
    delete config.ssl.certPath;
    delete config.ssl.keyPath;
    saveConfig(config);
    res.json({ success: true, message: '已切换为使用上传的证书' });
});

// API: 获取 SSL 状态
app.get('/api/ssl/status', requireAuth, (req, res) => {
    const uploadedCertPath = path.join(SSL_DIR, config.ssl.cert || 'server.crt');
    const uploadedKeyPath = path.join(SSL_DIR, config.ssl.key || 'server.key');
    
    // 优先使用本地路径
    const certPath = config.ssl.certPath || uploadedCertPath;
    const keyPath = config.ssl.keyPath || uploadedKeyPath;
    
    res.json({
        enabled: config.ssl.enabled,
        // 上传的文件状态
        hasUploadedCert: fs.existsSync(uploadedCertPath),
        hasUploadedKey: fs.existsSync(uploadedKeyPath),
        // 本地路径
        certPath: config.ssl.certPath || '',
        keyPath: config.ssl.keyPath || '',
        // 实际使用的文件是否存在
        certExists: fs.existsSync(certPath),
        keyExists: fs.existsSync(keyPath),
        // 使用模式
        mode: config.ssl.certPath ? 'path' : 'upload'
    });
});

// API: 重启服务
app.post('/api/restart', requireAuth, (req, res) => {
    res.json({ success: true, message: '服务即将重启...' });
    setTimeout(() => {
        process.exit(0);  // systemd 会自动重启
    }, 500);
});

// API: 获取请求日志
app.get('/api/logs', requireAuth, (req, res) => {
    res.json(requestLogs);
});

// API: 切换内置 provider 启用状态
app.post('/api/provider/toggle', requireAuth, (req, res) => {
    const { provider, enabled } = req.body;
    if (config.providers[provider]) {
        config.providers[provider].enabled = enabled;
        saveConfig(config);
        return res.json({ success: true });
    }
    res.status(400).json({ error: '未知 provider' });
});

// API: 更新 provider 配置（包括 apiKey 和 defaultModel）
app.post('/api/provider/config', requireAuth, (req, res) => {
    const { provider, apiKey, defaultModel } = req.body;
    
    // 检查内置 provider
    if (config.providers[provider]) {
        if (apiKey !== undefined) config.providers[provider].apiKey = apiKey;
        if (defaultModel !== undefined) {
            config.providers[provider].defaultModel = defaultModel;
            addModelToHistory(defaultModel);
        }
        saveConfig(config);
        return res.json({ success: true });
    }
    
    // 检查自定义 provider
    const custom = config.customProviders.find(p => p.id === provider);
    if (custom) {
        if (apiKey !== undefined) custom.apiKey = apiKey;
        if (defaultModel !== undefined) {
            custom.defaultModel = defaultModel;
            addModelToHistory(defaultModel);
        }
        saveConfig(config);
        return res.json({ success: true });
    }
    
    res.status(400).json({ error: '未知 provider' });
});

// API: 设置激活的 provider
app.post('/api/provider/activate', requireAuth, (req, res) => {
    const { provider } = req.body;
    
    // 检查是否存在且启用
    const builtIn = config.providers[provider];
    const custom = config.customProviders.find(p => p.id === provider);
    
    if (!builtIn && !custom) {
        return res.status(400).json({ error: '未知 provider' });
    }
    
    if ((builtIn && !builtIn.enabled) || (custom && !custom.enabled)) {
        return res.status(400).json({ error: 'Provider 未启用' });
    }
    
    config.activeProvider = provider;
    saveConfig(config);
    res.json({ success: true });
});

// API: 添加自定义 provider
app.post('/api/provider/add', requireAuth, (req, res) => {
    const { id, name, baseUrl, description, headerTemplate, apiKey, defaultModel } = req.body;
    if (!id || !name || !baseUrl) {
        return res.status(400).json({ error: '缺少必填字段' });
    }
    if (config.providers[id] || config.customProviders.find(p => p.id === id)) {
        return res.status(400).json({ error: 'Provider ID 已存在' });
    }
    config.customProviders.push({
        id,
        name,
        baseUrl,
        description: description || '',
        headerTemplate: headerTemplate || '',
        apiKey: apiKey || '',
        defaultModel: defaultModel || '',
        enabled: true
    });
    if (defaultModel) addModelToHistory(defaultModel);
    saveConfig(config);
    res.json({ success: true });
});

// API: 删除自定义 provider
app.post('/api/provider/delete', requireAuth, (req, res) => {
    const { id } = req.body;
    config.customProviders = config.customProviders.filter(p => p.id !== id);
    // 如果删除的是当前激活的，切回 openrouter
    if (config.activeProvider === id) {
        config.activeProvider = 'openrouter';
    }
    saveConfig(config);
    res.json({ success: true });
});

// API: 更新自定义 provider
app.post('/api/provider/update', requireAuth, (req, res) => {
    const { id, name, baseUrl, description, headerTemplate, enabled, apiKey, defaultModel } = req.body;
    const provider = config.customProviders.find(p => p.id === id);
    if (!provider) {
        return res.status(400).json({ error: 'Provider 不存在' });
    }
    if (name) provider.name = name;
    if (baseUrl) provider.baseUrl = baseUrl;
    if (description !== undefined) provider.description = description;
    if (headerTemplate !== undefined) provider.headerTemplate = headerTemplate;
    if (enabled !== undefined) provider.enabled = enabled;
    if (apiKey !== undefined) provider.apiKey = apiKey;
    if (defaultModel !== undefined) {
        provider.defaultModel = defaultModel;
        addModelToHistory(defaultModel);
    }
    saveConfig(config);
    res.json({ success: true });
});

// ============ 代理核心逻辑 ============

/**
 * 获取激活的 provider 配置
 * v2.1: 客户端 model 参数被忽略，始终使用服务端激活的 provider 和其默认 model
 */
function getActiveProviderConfig() {
    const provider = config.providers[config.activeProvider] 
        || config.customProviders.find(p => p.id === config.activeProvider);
    return {
        provider: config.activeProvider,
        model: provider?.defaultModel || ''
    };
}

/**
 * 获取 provider 配置
 */
function getProvider(providerId) {
    if (config.providers[providerId]?.enabled) {
        return { ...config.providers[providerId], id: providerId };
    }
    const custom = config.customProviders.find(p => p.id === providerId && p.enabled);
    return custom ? { ...custom } : null;
}

/**
 * 代理请求到目标 API
 */
async function proxyRequest(targetUrl, method, headers, body) {
    return new Promise((resolve, reject) => {
        const url = new URL(targetUrl);
        const isHttps = url.protocol === 'https:';
        const client = isHttps ? https : http;
        
        const options = {
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname + url.search,
            method,
            headers: {
                ...headers,
                'Host': url.hostname
            }
        };
        
        const req = client.request(options, (res) => {
            resolve(res);
        });
        
        req.on('error', reject);
        
        if (body) {
            req.write(typeof body === 'string' ? body : JSON.stringify(body));
        }
        req.end();
    });
}

// OpenAI 兼容的 chat completions 端点
app.post('/v1/chat/completions', async (req, res) => {
    const startTime = Date.now();
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    try {
        // v2.0: 验证 access token（可选）
        // 如果配置了 accessToken，则需要验证；否则跳过
        const authHeader = req.headers['authorization'];
        const clientToken = authHeader?.replace('Bearer ', '');
        
        // 如果配置了 accessToken 且客户端提供的不匹配，拒绝
        // 但如果客户端提供的是真实 API key 格式（以 sk- 开头），也接受（向后兼容）
        if (config.accessToken && clientToken !== config.accessToken) {
            // 检查是否是旧格式（直接传真实 API key）
            if (!clientToken?.startsWith('sk-')) {
                log('WARN', 'Invalid access token', { ip: clientIP });
                addRequestLog({ ip: clientIP, status: 401, error: 'Invalid access token' });
                return res.status(401).json({ error: { message: 'Invalid access token' } });
            }
        }
        
        const { model: requestedModel, ...restBody } = req.body;
        
        // v2.1: 忽略客户端传的 model，始终使用服务端激活的 provider
        const { provider: providerId, model: modelName } = getActiveProviderConfig();
        const provider = getProvider(providerId);
        
        log('INFO', 'Incoming request', { 
            ip: clientIP, 
            clientModel: requestedModel,  // 客户端传的（被忽略）
            activeProvider: providerId,
            activeModel: modelName,
            stream: !!restBody.stream 
        });
        
        if (!provider) {
            log('ERROR', 'Unknown provider', { providerId });
            addRequestLog({ ip: clientIP, model: requestedModel, provider: providerId, status: 400, error: `Unknown provider: ${providerId}` });
            return res.status(400).json({ 
                error: { message: `Unknown or disabled provider: ${providerId}` } 
            });
        }
        
        // v2.0: 使用服务端配置的 API Key
        const apiKey = provider.apiKey;
        if (!apiKey) {
            log('ERROR', 'No API key configured', { providerId });
            addRequestLog({ ip: clientIP, model: requestedModel, provider: providerId, status: 500, error: 'No API key configured for this provider' });
            return res.status(500).json({ 
                error: { message: `No API key configured for provider: ${providerId}. Please configure it in the admin panel.` } 
            });
        }
        
        // 如果没有指定 model，使用默认
        const finalModel = modelName || provider.defaultModel;
        if (!finalModel) {
            log('ERROR', 'No model specified', { providerId });
            addRequestLog({ ip: clientIP, model: requestedModel, provider: providerId, status: 400, error: 'No model specified and no default model configured' });
            return res.status(400).json({ 
                error: { message: `No model specified and no default model configured for provider: ${providerId}` } 
            });
        }
        
        const maskedKey = apiKey.slice(0, 8) + '...' + apiKey.slice(-4);
        
        let targetUrl, targetHeaders;
        
        if (providerId === 'openrouter') {
            targetUrl = `${provider.baseUrl}/chat/completions`;
            targetHeaders = {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
                'HTTP-Referer': req.headers['referer'] || 'https://llm-proxy.local',
                'X-Title': 'LLM Proxy'
            };
        } else if (providerId === 'poe') {
            targetUrl = `${provider.baseUrl}/chat/completions`;
            targetHeaders = {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            };
            
            // Poe 不支持某些参数
            delete restBody.tools;
            delete restBody.tool_choice;
            delete restBody.stream_options;
            delete restBody.store;
            delete restBody.max_completion_tokens;
            
            if (restBody.messages) {
                restBody.messages = restBody.messages.map(msg => {
                    if (msg.role === 'developer') {
                        return { ...msg, role: 'system' };
                    }
                    return msg;
                });
            }
        } else {
            targetUrl = `${provider.baseUrl}/chat/completions`;
            targetHeaders = {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            };
            
            if (provider.headerTemplate) {
                try {
                    const customHeaders = JSON.parse(provider.headerTemplate.replace(/\$API_KEY/g, apiKey));
                    Object.assign(targetHeaders, customHeaders);
                } catch (e) {
                    log('ERROR', 'Header template parse error', { error: e.message });
                }
            }
        }
        
        const requestBody = { model: finalModel, ...restBody };
        
        log('INFO', 'Proxying request', { 
            provider: providerId, 
            model: finalModel, 
            targetUrl,
            apiKey: maskedKey,
            messageCount: requestBody.messages?.length,
            stream: requestBody.stream
        });
        
        const proxyRes = await proxyRequest(targetUrl, 'POST', targetHeaders, requestBody);
        
        log('INFO', 'Upstream response', { 
            status: proxyRes.statusCode, 
            contentType: proxyRes.headers['content-type']
        });
        
        res.status(proxyRes.statusCode);
        
        if (!req.body.stream) {
            let responseData = '';
            proxyRes.on('data', chunk => responseData += chunk);
            proxyRes.on('end', () => {
                const duration = Date.now() - startTime;
                try {
                    const parsed = JSON.parse(responseData);
                    if (parsed.error) {
                        log('ERROR', 'Upstream error', { error: parsed.error, duration });
                        addRequestLog({ 
                            ip: clientIP, 
                            model: finalModel,
                            provider: providerId, 
                            status: proxyRes.statusCode, 
                            error: parsed.error.message || JSON.stringify(parsed.error),
                            duration 
                        });
                    } else {
                        log('INFO', 'Request completed', { duration, usage: parsed.usage });
                        addRequestLog({ 
                            ip: clientIP, 
                            model: finalModel,
                            provider: providerId, 
                            status: proxyRes.statusCode, 
                            usage: parsed.usage,
                            duration 
                        });
                    }
                } catch (e) {
                    addRequestLog({ 
                        ip: clientIP, 
                        model: finalModel,
                        provider: providerId, 
                        status: proxyRes.statusCode, 
                        error: responseData.slice(0, 200),
                        duration 
                    });
                }
                res.setHeader('Content-Type', 'application/json');
                res.send(responseData);
            });
        } else {
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            
            if (proxyRes.statusCode !== 200) {
                let errorData = '';
                proxyRes.on('data', chunk => errorData += chunk);
                proxyRes.on('end', () => {
                    const duration = Date.now() - startTime;
                    let errorMsg = errorData.slice(0, 200);
                    try {
                        const parsed = JSON.parse(errorData);
                        errorMsg = parsed.error?.message || errorData.slice(0, 200);
                    } catch (e) {}
                    
                    addRequestLog({ 
                        ip: clientIP, 
                        model: finalModel,
                        provider: providerId, 
                        status: proxyRes.statusCode, 
                        stream: true,
                        error: errorMsg,
                        duration 
                    });
                    res.end(errorData);
                });
            } else {
                const duration = Date.now() - startTime;
                addRequestLog({ 
                    ip: clientIP, 
                    model: finalModel,
                    provider: providerId, 
                    status: proxyRes.statusCode, 
                    stream: true,
                    duration 
                });
                proxyRes.pipe(res);
            }
        }
        
    } catch (error) {
        log('ERROR', 'Proxy exception', { error: error.message });
        addRequestLog({ ip: req.socket.remoteAddress, status: 500, error: error.message });
        res.status(500).json({ error: { message: error.message } });
    }
});

// Models 端点
app.get('/v1/models', async (req, res) => {
    // v2.0: 返回当前激活 provider 的默认 model
    const provider = getProvider(config.activeProvider);
    
    const models = [{
        id: provider?.defaultModel || 'unknown',
        object: 'model',
        created: Math.floor(Date.now() / 1000),
        owned_by: config.activeProvider
    }];
    
    res.json({ data: models, object: 'list' });
});

// 健康检查
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        activeProvider: config.activeProvider,
        providers: [
            ...Object.keys(config.providers).filter(k => config.providers[k].enabled),
            ...config.customProviders.filter(p => p.enabled).map(p => p.id)
        ]
    });
});

// ============ HTML 模板 ============

const i18n = {
    zh: {
        title: 'LLM Proxy',
        login: '登录',
        logout: '退出登录',
        password: '密码',
        enterPassword: '输入密码',
        wrongPassword: '密码错误',
        console: '控制台',
        requestLogs: '请求日志',
        refresh: '刷新',
        apiEndpoint: 'API 端点',
        apiEndpointDesc: '客户端配置说明：',
        baseUrl: 'Base URL',
        modelFormat: 'Model 格式',
        example: '例如',
        accessToken: '访问令牌',
        accessTokenDesc: 'Clawdbot 用这个作为 API Key（替代真实 key）',
        activeProvider: '当前激活',
        activate: '激活',
        builtinProviders: '内置 Providers',
        customProviders: '自定义 Providers',
        addProvider: '添加 Provider',
        providerId: 'ID',
        providerName: '名称',
        providerDesc: '描述',
        providerApiKey: 'API Key',
        providerModel: '默认 Model',
        customHeaders: '自定义 Headers (JSON)',
        add: '添加',
        save: '保存',
        delete: '删除',
        enable: '启用',
        disable: '禁用',
        disabled: '已禁用',
        changePassword: '修改密码',
        oldPassword: '原密码',
        newPassword: '新密码',
        updatePassword: '更新',
        passwordUpdated: '密码已更新',
        updated: '已更新',
        saved: '已保存',
        deleted: '已删除',
        providerAdded: 'Provider 已添加',
        fillRequired: '请填写必填字段',
        confirmDelete: '确定删除?',
        noLogs: '暂无日志',
        noCustomProviders: '暂无',
        tokens: 'tokens',
        configured: '已配置',
        notConfigured: '未配置',
        langSwitch: 'English',
        // 服务器设置
        serverSettings: '服务器设置',
        port: '端口号',
        sslSettings: 'SSL/HTTPS 设置',
        sslMethod1: '方式一：指定本地文件路径',
        sslMethod2: '方式二：上传证书文件',
        certPath: '证书路径',
        keyPath: '私钥路径',
        certPathPlaceholder: '证书路径，如 /etc/ssl/server.crt',
        keyPathPlaceholder: '私钥路径，如 /etc/ssl/server.key',
        savePath: '保存路径',
        clearPath: '清除路径',
        certFile: '证书文件 (.crt/.pem)',
        keyFile: '私钥文件 (.key)',
        uploadCert: '上传证书',
        enableHttps: '启用 HTTPS',
        disableHttps: '禁用 HTTPS',
        restartServer: '重启服务',
        confirmRestart: '确定要重启服务吗？',
        restarting: '服务正在重启，请稍后刷新页面...',
        protocol: '协议',
        mode: '模式',
        modePath: '本地路径',
        modeUpload: '上传文件',
        cert: '证书',
        key: '私钥',
        pathSaved: 'SSL 路径已保存',
        pathCleared: '已切换为使用上传的证书',
        sslEnabled: 'SSL 已启用，重启服务后生效',
        sslDisabled: 'SSL 已禁用，重启服务后生效',
        portSaved: '端口已更新，重启服务后生效',
        selectFile: '请选择要上传的文件',
        enterPath: '请输入至少一个路径',
        tokenMinLength: 'Token 至少8位'
    },
    en: {
        title: 'LLM Proxy',
        login: 'Login',
        logout: 'Logout',
        password: 'Password',
        enterPassword: 'Enter password',
        wrongPassword: 'Wrong password',
        console: 'Console',
        requestLogs: 'Request Logs',
        refresh: 'Refresh',
        apiEndpoint: 'API Endpoint',
        apiEndpointDesc: 'Use this in your Clawdbot config:',
        baseUrl: 'Base URL',
        modelFormat: 'Model Format',
        example: 'Example',
        accessToken: 'Access Token',
        accessTokenDesc: 'Clawdbot uses this as API Key (replaces real key)',
        activeProvider: 'Active',
        activate: 'Activate',
        builtinProviders: 'Built-in Providers',
        customProviders: 'Custom Providers',
        addProvider: 'Add Provider',
        providerId: 'ID',
        providerName: 'Name',
        providerDesc: 'Description',
        providerApiKey: 'API Key',
        providerModel: 'Default Model',
        customHeaders: 'Custom Headers (JSON)',
        add: 'Add',
        save: 'Save',
        delete: 'Delete',
        enable: 'Enable',
        disable: 'Disable',
        disabled: 'Disabled',
        changePassword: 'Change Password',
        oldPassword: 'Current Password',
        newPassword: 'New Password',
        updatePassword: 'Update',
        passwordUpdated: 'Password updated',
        updated: 'Updated',
        saved: 'Saved',
        deleted: 'Deleted',
        providerAdded: 'Provider added',
        fillRequired: 'Please fill required fields',
        confirmDelete: 'Confirm delete?',
        noLogs: 'No logs',
        noCustomProviders: 'None',
        tokens: 'tokens',
        configured: 'Configured',
        notConfigured: 'Not configured',
        langSwitch: '中文',
        // Server settings
        serverSettings: 'Server Settings',
        port: 'Port',
        sslSettings: 'SSL/HTTPS Settings',
        sslMethod1: 'Method 1: Specify local file path',
        sslMethod2: 'Method 2: Upload certificate files',
        certPath: 'Certificate path',
        keyPath: 'Private key path',
        certPathPlaceholder: 'Certificate path, e.g. /etc/ssl/server.crt',
        keyPathPlaceholder: 'Private key path, e.g. /etc/ssl/server.key',
        savePath: 'Save Path',
        clearPath: 'Clear Path',
        certFile: 'Certificate file (.crt/.pem)',
        keyFile: 'Private key file (.key)',
        uploadCert: 'Upload Certificate',
        enableHttps: 'Enable HTTPS',
        disableHttps: 'Disable HTTPS',
        restartServer: 'Restart Server',
        confirmRestart: 'Are you sure you want to restart the server?',
        restarting: 'Server is restarting, please refresh later...',
        protocol: 'Protocol',
        mode: 'Mode',
        modePath: 'Local Path',
        modeUpload: 'Uploaded File',
        cert: 'Cert',
        key: 'Key',
        pathSaved: 'SSL path saved',
        pathCleared: 'Switched to use uploaded certificate',
        sslEnabled: 'SSL enabled, restart to apply',
        sslDisabled: 'SSL disabled, restart to apply',
        portSaved: 'Port updated, restart to apply',
        selectFile: 'Please select a file to upload',
        enterPath: 'Please enter at least one path',
        tokenMinLength: 'Token must be at least 8 characters'
    }
};

function getLoginHTML() {
    return `<!DOCTYPE html>
<html><head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Proxy - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-box { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); padding: 40px; border-radius: 20px; width: 360px; }
        h1 { color: #fff; text-align: center; margin-bottom: 30px; }
        h1 span { color: #00d9ff; }
        .lang-switch { text-align: center; margin-bottom: 20px; }
        .lang-switch a { color: #00d9ff; text-decoration: none; cursor: pointer; }
        input { width: 100%; padding: 15px; border: none; border-radius: 10px; background: rgba(255,255,255,0.1); color: #fff; font-size: 1em; margin-bottom: 20px; }
        input:focus { outline: 2px solid #00d9ff; }
        button { width: 100%; padding: 15px; border: none; border-radius: 10px; background: #00d9ff; color: #000; font-weight: bold; cursor: pointer; }
        .error { color: #ff4757; text-align: center; margin-top: 15px; display: none; }
    </style>
</head><body>
    <div class="login-box">
        <h1>🤖 <span>LLM</span> Proxy</h1>
        <div class="lang-switch"><a onclick="toggleLang()" id="langBtn">English</a></div>
        <form id="loginForm">
            <input type="password" name="password" id="pwd" placeholder="Password" required autofocus>
            <button type="submit" id="loginBtn">Login</button>
        </form>
        <p class="error" id="error"></p>
    </div>
    <script>
        let lang = localStorage.getItem('llm-proxy-lang') || 'zh';
        const t = ${JSON.stringify(i18n)};
        function updateUI() {
            document.getElementById('pwd').placeholder = t[lang].enterPassword;
            document.getElementById('loginBtn').textContent = t[lang].login;
            document.getElementById('langBtn').textContent = t[lang].langSwitch;
        }
        function toggleLang() { lang = lang === 'zh' ? 'en' : 'zh'; localStorage.setItem('llm-proxy-lang', lang); updateUI(); }
        updateUI();
        document.getElementById('loginForm').onsubmit = async (e) => {
            e.preventDefault();
            const res = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: e.target.password.value }) });
            if (res.ok) location.href = '/';
            else { document.getElementById('error').style.display = 'block'; document.getElementById('error').textContent = t[lang].wrongPassword; }
        };
    </script>
</body></html>`;
}

function getAdminHTML() {
    return `<!DOCTYPE html>
<html><head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Proxy - Console</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; }
        .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #333; }
        h1 { font-size: 1.5em; } h1 span { color: #00d9ff; }
        .header-right { display: flex; gap: 15px; align-items: center; }
        .lang-switch { color: #00d9ff; cursor: pointer; }
        .logout { color: #888; text-decoration: none; }
        .section { background: #16213e; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
        .section h2 { margin-bottom: 15px; font-size: 1.1em; display: flex; justify-content: space-between; align-items: center; }
        .provider-item { background: #0f0f23; padding: 15px; border-radius: 8px; margin-bottom: 10px; }
        .provider-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .provider-name { font-weight: bold; color: #00d9ff; }
        .provider-name.active::after { content: ' ✓'; color: #2ed573; }
        .provider-meta { color: #888; font-size: 0.9em; }
        .provider-config { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }
        .provider-config input { padding: 8px; border: none; border-radius: 5px; background: #1a1a2e; color: #fff; font-size: 0.9em; }
        .provider-config input:focus { outline: 1px solid #00d9ff; }
        .provider-config input::-webkit-calendar-picker-indicator { filter: invert(1); }
        .provider-actions { display: flex; gap: 8px; margin-top: 10px; }
        .btn { padding: 6px 12px; border: none; border-radius: 5px; cursor: pointer; font-size: 0.85em; }
        .btn-primary { background: #00d9ff; color: #000; }
        .btn-secondary { background: #333; color: #fff; }
        .btn-danger { background: #ff4757; color: #fff; }
        .btn-success { background: #2ed573; color: #000; }
        .endpoint-box { background: #0f0f23; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 0.9em; }
        .endpoint-box code { color: #00d9ff; }
        .log-item { padding: 8px 10px; background: #0f0f23; margin-bottom: 5px; border-radius: 5px; border-left: 3px solid #2ed573; font-size: 0.85em; font-family: monospace; }
        .log-item.error { border-left-color: #ff4757; }
        .log-time { color: #888; }
        .log-status { font-weight: bold; }
        .log-status.ok { color: #2ed573; }
        .log-status.err { color: #ff4757; }
        .log-model { color: #00d9ff; }
        .log-error { color: #ff4757; margin-top: 5px; }
        .message { padding: 10px; border-radius: 5px; margin-bottom: 15px; display: none; }
        .message.success { background: rgba(46,213,115,0.2); color: #2ed573; display: block; }
        .message.error { background: rgba(255,71,87,0.2); color: #ff4757; display: block; }
        .form-row { display: flex; gap: 10px; margin-bottom: 10px; }
        .form-row input { flex: 1; padding: 10px; border: none; border-radius: 5px; background: #0f0f23; color: #fff; }
        .form-row input:focus { outline: 1px solid #00d9ff; }
        .status-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75em; }
        .status-badge.ok { background: rgba(46,213,115,0.2); color: #2ed573; }
        .status-badge.warn { background: rgba(255,165,0,0.2); color: orange; }
        .toggle { position: relative; width: 44px; height: 22px; }
        .toggle input { display: none; }
        .toggle label { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: #333; border-radius: 11px; cursor: pointer; }
        .toggle label:after { content: ''; position: absolute; width: 18px; height: 18px; background: #fff; border-radius: 50%; top: 2px; left: 2px; transition: 0.2s; }
        .toggle input:checked + label { background: #00d9ff; }
        .toggle input:checked + label:after { left: 24px; }
    </style>
</head><body>
    <div class="container">
        <div class="header">
            <h1>🤖 <span>LLM</span> Proxy <span id="hConsole">控制台</span></h1>
            <div class="header-right">
                <span class="lang-switch" onclick="toggleLang()" id="langBtn">EN</span>
                <a href="/logout" class="logout" id="logoutBtn">退出</a>
            </div>
        </div>
        <div id="msg" class="message"></div>
        
        <!-- Model 历史记录 datalist -->
        <datalist id="modelHistory"></datalist>
        
        <div class="section">
            <h2><span id="lblLogs">📋 请求日志</span> <button class="btn btn-secondary" onclick="loadLogs()" id="btnRefresh">刷新</button></h2>
            <div id="logList" style="max-height:250px;overflow-y:auto;"></div>
        </div>
        
        <div class="section">
            <h2 id="lblEndpoint">📡 API 端点</h2>
            <p style="color:#888;margin-bottom:10px;" id="lblEndpointDesc">客户端配置说明：</p>
            <div class="endpoint-box">
                <p><strong>Base URL:</strong> <code>http://YOUR_IP:1180/v1</code></p>
                <p style="margin-top:8px;"><strong>API Key:</strong> <code id="showToken">llm-proxy-token</code></p>
                <p style="margin-top:8px;"><strong>Model:</strong> <code>provider名称</code> 或 <code>provider/model</code></p>
                <p style="margin-top:5px;color:#888;">例: <code>openrouter</code> 或 <code>openrouter/anthropic/claude-3.5-sonnet</code></p>
            </div>
            <div style="margin-top:15px;">
                <label id="lblAccessToken">访问令牌：</label>
                <div class="form-row" style="margin-top:5px;">
                    <input type="text" id="accessToken" placeholder="llm-proxy-token">
                    <button class="btn btn-primary" onclick="saveAccessToken()" id="btnSaveToken">保存</button>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 id="lblBuiltin">🔌 内置 Providers</h2>
            <div id="builtinProviders"></div>
        </div>
        
        <div class="section">
            <h2 id="lblCustom">➕ 自定义 Providers</h2>
            <div id="customProviders"></div>
            <div style="margin-top:15px;padding-top:15px;border-top:1px solid #333;">
                <h3 style="margin-bottom:10px;" id="lblAdd">添加 Provider</h3>
                <div class="form-row">
                    <input type="text" id="newId" placeholder="ID">
                    <input type="text" id="newName" placeholder="名称">
                </div>
                <div class="form-row">
                    <input type="text" id="newUrl" placeholder="Base URL">
                </div>
                <div class="form-row">
                    <input type="text" id="newKey" placeholder="API Key">
                    <input type="text" id="newModel" placeholder="默认 Model" list="modelHistory">
                </div>
                <button class="btn btn-primary" onclick="addProvider()" id="btnAdd">添加</button>
            </div>
        </div>
        
        <div class="section">
            <h2 id="lblPwd">🔐 修改密码</h2>
            <div class="form-row">
                <input type="password" id="oldPwd" placeholder="原密码">
                <input type="password" id="newPwd" placeholder="新密码">
                <button class="btn btn-primary" onclick="changePwd()" id="btnPwd">更新</button>
            </div>
        </div>
        
        <div class="section">
            <h2 id="lblServer">⚙️ <span id="lblServerText">服务器设置</span></h2>
            <div class="form-row">
                <div style="flex:1;">
                    <label style="color:#888;font-size:0.9em;" id="lblPort">端口号</label>
                    <div class="form-row" style="margin-top:5px;margin-bottom:0;">
                        <input type="number" id="serverPort" placeholder="1180" min="1" max="65535">
                        <button class="btn btn-primary" onclick="savePort()" id="btnSavePort">保存</button>
                    </div>
                </div>
            </div>
            <div style="margin-top:15px;padding-top:15px;border-top:1px solid #333;">
                <label style="color:#888;font-size:0.9em;" id="lblSSL">SSL/HTTPS 设置</label>
                <div id="sslStatus" style="margin-top:10px;padding:10px;background:#0f0f23;border-radius:5px;font-size:0.9em;"></div>
                
                <div style="margin-top:15px;">
                    <label style="color:#00d9ff;font-size:0.85em;" id="lblMethod1">方式一：指定本地文件路径</label>
                    <div class="form-row" style="margin-top:8px;">
                        <input type="text" id="sslCertPath" placeholder="证书路径，如 /etc/ssl/server.crt" style="font-size:0.9em;">
                    </div>
                    <div class="form-row">
                        <input type="text" id="sslKeyPath" placeholder="私钥路径，如 /etc/ssl/server.key" style="font-size:0.9em;">
                    </div>
                    <div class="form-row">
                        <button class="btn btn-primary" onclick="saveSSLPath()" id="btnSavePath">保存路径</button>
                        <button class="btn btn-secondary" onclick="clearSSLPath()" id="btnClearPath">清除路径</button>
                    </div>
                </div>
                
                <div style="margin-top:15px;">
                    <label style="color:#00d9ff;font-size:0.85em;" id="lblMethod2">方式二：上传证书文件</label>
                    <div class="form-row" style="margin-top:8px;">
                        <div style="flex:1;">
                            <label style="color:#888;font-size:0.85em;" id="lblCertFile">证书文件 (.crt/.pem)</label>
                            <input type="file" id="sslCert" accept=".crt,.pem,.cer" style="margin-top:5px;font-size:0.85em;">
                        </div>
                        <div style="flex:1;">
                            <label style="color:#888;font-size:0.85em;" id="lblKeyFile">私钥文件 (.key)</label>
                            <input type="file" id="sslKey" accept=".key,.pem" style="margin-top:5px;font-size:0.85em;">
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="uploadSSL()" id="btnUpload">上传证书</button>
                </div>
                
                <div class="form-row" style="margin-top:15px;padding-top:15px;border-top:1px solid #333;">
                    <button class="btn btn-success" id="btnEnableSSL" onclick="toggleSSL(true)">启用 HTTPS</button>
                    <button class="btn btn-secondary" id="btnDisableSSL" onclick="toggleSSL(false)">禁用 HTTPS</button>
                    <button class="btn btn-danger" onclick="restartServer()" id="btnRestart">重启服务</button>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let cfg = {};
        let lang = localStorage.getItem('llm-proxy-lang') || 'zh';
        const t = ${JSON.stringify(i18n)};
        
        function updateUI() {
            const l = t[lang];
            document.getElementById('hConsole').textContent = l.console;
            document.getElementById('langBtn').textContent = l.langSwitch;
            document.getElementById('logoutBtn').textContent = l.logout;
            document.getElementById('lblLogs').textContent = '📋 ' + l.requestLogs;
            document.getElementById('btnRefresh').textContent = l.refresh;
            document.getElementById('lblEndpoint').textContent = '📡 ' + l.apiEndpoint;
            document.getElementById('lblEndpointDesc').textContent = l.apiEndpointDesc;
            document.getElementById('lblAccessToken').textContent = l.accessToken + '：';
            document.getElementById('btnSaveToken').textContent = l.save;
            document.getElementById('lblBuiltin').textContent = '🔌 ' + l.builtinProviders;
            document.getElementById('lblCustom').textContent = '➕ ' + l.customProviders;
            document.getElementById('lblAdd').textContent = l.addProvider;
            document.getElementById('btnAdd').textContent = l.add;
            document.getElementById('lblPwd').textContent = '🔐 ' + l.changePassword;
            document.getElementById('btnPwd').textContent = l.updatePassword;
            // 服务器设置
            document.getElementById('lblServerText').textContent = l.serverSettings;
            document.getElementById('lblPort').textContent = l.port;
            document.getElementById('btnSavePort').textContent = l.save;
            document.getElementById('lblSSL').textContent = l.sslSettings;
            document.getElementById('lblMethod1').textContent = l.sslMethod1;
            document.getElementById('lblMethod2').textContent = l.sslMethod2;
            document.getElementById('sslCertPath').placeholder = l.certPathPlaceholder;
            document.getElementById('sslKeyPath').placeholder = l.keyPathPlaceholder;
            document.getElementById('btnSavePath').textContent = l.savePath;
            document.getElementById('btnClearPath').textContent = l.clearPath;
            document.getElementById('lblCertFile').textContent = l.certFile;
            document.getElementById('lblKeyFile').textContent = l.keyFile;
            document.getElementById('btnUpload').textContent = l.uploadCert;
            document.getElementById('btnEnableSSL').textContent = l.enableHttps;
            document.getElementById('btnDisableSSL').textContent = l.disableHttps;
            document.getElementById('btnRestart').textContent = l.restartServer;
            renderProviders();
            loadLogs();
        }
        
        function toggleLang() { lang = lang === 'zh' ? 'en' : 'zh'; localStorage.setItem('llm-proxy-lang', lang); updateUI(); }
        
        async function loadConfig() {
            const res = await fetch('/api/config');
            cfg = await res.json();
            document.getElementById('accessToken').value = cfg.accessToken || '';
            document.getElementById('showToken').textContent = cfg.accessToken || 'llm-proxy-token';
            document.getElementById('serverPort').value = cfg.port || 1180;
            renderProviders();
            loadSSLStatus();
        }
        
        async function loadSSLStatus() {
            const res = await fetch('/api/ssl/status');
            const ssl = await res.json();
            const l = t[lang];
            const statusEl = document.getElementById('sslStatus');
            const protocol = ssl.enabled ? 'HTTPS' : 'HTTP';
            const certStatus = ssl.certExists ? '✅' : '❌';
            const keyStatus = ssl.keyExists ? '✅' : '❌';
            const modeText = ssl.mode === 'path' ? l.modePath : l.modeUpload;
            statusEl.innerHTML = \`
                <div style="display:flex;gap:20px;flex-wrap:wrap;">
                    <span>\${l.protocol}: <strong style="color:\${ssl.enabled ? '#2ed573' : '#00d9ff'};">\${protocol}</strong></span>
                    <span>\${l.mode}: <strong>\${modeText}</strong></span>
                    <span>\${l.cert}: \${certStatus}</span>
                    <span>\${l.key}: \${keyStatus}</span>
                </div>
                \${ssl.certPath ? \`<div style="margin-top:8px;color:#888;font-size:0.85em;">\${l.certPath}: \${ssl.certPath}</div>\` : ''}
                \${ssl.keyPath ? \`<div style="color:#888;font-size:0.85em;">\${l.keyPath}: \${ssl.keyPath}</div>\` : ''}
            \`;
            document.getElementById('btnEnableSSL').style.display = ssl.enabled ? 'none' : 'inline-block';
            document.getElementById('btnDisableSSL').style.display = ssl.enabled ? 'inline-block' : 'none';
            
            // 填充路径输入框
            document.getElementById('sslCertPath').value = ssl.certPath || '';
            document.getElementById('sslKeyPath').value = ssl.keyPath || '';
        }
        
        function renderProviders() {
            const l = t[lang];
            
            // 更新 model 历史记录 datalist
            const historyHtml = (cfg.modelHistory || []).map(m => \`<option value="\${m}">\`).join('');
            document.getElementById('modelHistory').innerHTML = historyHtml;
            
            let html = '';
            for (const [id, p] of Object.entries(cfg.providers || {})) {
                const isActive = id === cfg.activeProvider;
                html += \`<div class="provider-item">
                    <div class="provider-header">
                        <span class="provider-name \${isActive ? 'active' : ''}">\${p.name}</span>
                        <div style="display:flex;gap:10px;align-items:center;">
                            <span class="status-badge \${p.apiKey ? 'ok' : 'warn'}">\${p.apiKey ? l.configured : l.notConfigured}</span>
                            <div class="toggle">
                                <input type="checkbox" id="tog-\${id}" \${p.enabled ? 'checked' : ''} onchange="toggleBuiltin('\${id}', this.checked)">
                                <label for="tog-\${id}"></label>
                            </div>
                        </div>
                    </div>
                    <div class="provider-meta">\${p.description}</div>
                    <div class="provider-config">
                        <input type="text" id="key-\${id}" placeholder="API Key" value="\${p.apiKeyMasked || ''}">
                        <input type="text" id="model-\${id}" placeholder="Default Model" value="\${p.defaultModel || ''}" list="modelHistory">
                    </div>
                    <div class="provider-actions">
                        <button class="btn btn-primary" onclick="saveBuiltin('\${id}')">\${l.save}</button>
                        \${!isActive && p.enabled ? \`<button class="btn btn-success" onclick="activate('\${id}')">\${l.activate}</button>\` : ''}
                    </div>
                </div>\`;
            }
            document.getElementById('builtinProviders').innerHTML = html;
            
            let customHtml = '';
            for (const p of cfg.customProviders || []) {
                const isActive = p.id === cfg.activeProvider;
                customHtml += \`<div class="provider-item">
                    <div class="provider-header">
                        <span class="provider-name \${isActive ? 'active' : ''}">\${p.name} <span style="color:#888;font-weight:normal;">(\${p.id})</span></span>
                        <span class="status-badge \${p.apiKey ? 'ok' : 'warn'}">\${p.apiKey ? l.configured : l.notConfigured}</span>
                    </div>
                    <div class="provider-meta">\${p.baseUrl}</div>
                    <div class="provider-config">
                        <input type="text" id="ckey-\${p.id}" placeholder="API Key" value="\${p.apiKeyMasked || ''}">
                        <input type="text" id="cmodel-\${p.id}" placeholder="Default Model" value="\${p.defaultModel || ''}" list="modelHistory">
                    </div>
                    <div class="provider-actions">
                        <button class="btn btn-primary" onclick="saveCustom('\${p.id}')">\${l.save}</button>
                        \${!isActive && p.enabled ? \`<button class="btn btn-success" onclick="activate('\${p.id}')">\${l.activate}</button>\` : ''}
                        <button class="btn btn-secondary" onclick="toggleCustom('\${p.id}', \${!p.enabled})">\${p.enabled ? l.disable : l.enable}</button>
                        <button class="btn btn-danger" onclick="delCustom('\${p.id}')">\${l.delete}</button>
                    </div>
                </div>\`;
            }
            document.getElementById('customProviders').innerHTML = customHtml || '<p style="color:#888;">' + l.noCustomProviders + '</p>';
        }
        
        async function toggleBuiltin(id, enabled) {
            await fetch('/api/provider/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider: id, enabled }) });
            loadConfig();
            showMsg(t[lang].updated, 'success');
        }
        
        async function saveBuiltin(id) {
            const apiKey = document.getElementById('key-' + id).value;
            const defaultModel = document.getElementById('model-' + id).value;
            // 如果是 masked 值，不更新 apiKey
            const body = { provider: id, defaultModel };
            if (!apiKey.includes('...')) body.apiKey = apiKey;
            await fetch('/api/provider/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            loadConfig();
            showMsg(t[lang].saved, 'success');
        }
        
        async function saveCustom(id) {
            const apiKey = document.getElementById('ckey-' + id).value;
            const defaultModel = document.getElementById('cmodel-' + id).value;
            const body = { id, defaultModel };
            if (!apiKey.includes('...')) body.apiKey = apiKey;
            await fetch('/api/provider/update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            loadConfig();
            showMsg(t[lang].saved, 'success');
        }
        
        async function activate(id) {
            await fetch('/api/provider/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ provider: id }) });
            loadConfig();
            showMsg(t[lang].updated, 'success');
        }
        
        async function toggleCustom(id, enabled) {
            await fetch('/api/provider/update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, enabled }) });
            loadConfig();
        }
        
        async function delCustom(id) {
            if (!confirm(t[lang].confirmDelete)) return;
            await fetch('/api/provider/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
            loadConfig();
            showMsg(t[lang].deleted, 'success');
        }
        
        async function addProvider() {
            const id = document.getElementById('newId').value.trim();
            const name = document.getElementById('newName').value.trim();
            const baseUrl = document.getElementById('newUrl').value.trim();
            const apiKey = document.getElementById('newKey').value.trim();
            const defaultModel = document.getElementById('newModel').value.trim();
            if (!id || !name || !baseUrl) return showMsg(t[lang].fillRequired, 'error');
            const res = await fetch('/api/provider/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, name, baseUrl, apiKey, defaultModel }) });
            if (res.ok) {
                document.getElementById('newId').value = '';
                document.getElementById('newName').value = '';
                document.getElementById('newUrl').value = '';
                document.getElementById('newKey').value = '';
                document.getElementById('newModel').value = '';
                loadConfig();
                showMsg(t[lang].providerAdded, 'success');
            } else {
                const data = await res.json();
                showMsg(data.error, 'error');
            }
        }
        
        async function saveAccessToken() {
            const token = document.getElementById('accessToken').value.trim();
            if (!token || token.length < 8) return showMsg(t[lang].tokenMinLength, 'error');
            await fetch('/api/access-token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessToken: token }) });
            loadConfig();
            showMsg(t[lang].saved, 'success');
        }
        
        async function changePwd() {
            const oldPassword = document.getElementById('oldPwd').value;
            const newPassword = document.getElementById('newPwd').value;
            const res = await fetch('/api/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oldPassword, newPassword }) });
            if (res.ok) {
                showMsg(t[lang].passwordUpdated, 'success');
                setTimeout(() => location.href = '/login', 1500);
            } else {
                const data = await res.json();
                showMsg(data.error, 'error');
            }
        }
        
        async function savePort() {
            const port = document.getElementById('serverPort').value;
            const res = await fetch('/api/port', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port }) });
            const data = await res.json();
            if (res.ok) {
                showMsg(t[lang].portSaved, 'success');
            } else {
                showMsg(data.error, 'error');
            }
        }
        
        async function uploadSSL() {
            const certFile = document.getElementById('sslCert').files[0];
            const keyFile = document.getElementById('sslKey').files[0];
            if (!certFile && !keyFile) return showMsg(t[lang].selectFile, 'error');
            
            const formData = new FormData();
            if (certFile) formData.append('cert', certFile);
            if (keyFile) formData.append('key', keyFile);
            
            const res = await fetch('/api/ssl/upload', { method: 'POST', body: formData });
            const data = await res.json();
            if (res.ok) {
                showMsg(t[lang].saved, 'success');
                loadSSLStatus();
                document.getElementById('sslCert').value = '';
                document.getElementById('sslKey').value = '';
            } else {
                showMsg(data.error, 'error');
            }
        }
        
        async function toggleSSL(enabled) {
            const res = await fetch('/api/ssl/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
            const data = await res.json();
            if (res.ok) {
                showMsg(enabled ? t[lang].sslEnabled : t[lang].sslDisabled, 'success');
                loadSSLStatus();
            } else {
                showMsg(data.error, 'error');
            }
        }
        
        async function saveSSLPath() {
            const certPath = document.getElementById('sslCertPath').value.trim();
            const keyPath = document.getElementById('sslKeyPath').value.trim();
            if (!certPath && !keyPath) return showMsg(t[lang].enterPath, 'error');
            
            const res = await fetch('/api/ssl/path', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ certPath, keyPath }) });
            const data = await res.json();
            if (res.ok) {
                showMsg(t[lang].pathSaved, 'success');
                loadSSLStatus();
            } else {
                showMsg(data.error, 'error');
            }
        }
        
        async function clearSSLPath() {
            const res = await fetch('/api/ssl/clear-path', { method: 'POST' });
            const data = await res.json();
            if (res.ok) {
                showMsg(t[lang].pathCleared, 'success');
                document.getElementById('sslCertPath').value = '';
                document.getElementById('sslKeyPath').value = '';
                loadSSLStatus();
            } else {
                showMsg(data.error, 'error');
            }
        }
        
        async function restartServer() {
            if (!confirm(t[lang].confirmRestart)) return;
            await fetch('/api/restart', { method: 'POST' });
            showMsg(t[lang].restarting, 'success');
            setTimeout(() => location.reload(), 3000);
        }
        
        async function loadLogs() {
            const l = t[lang];
            const res = await fetch('/api/logs');
            const logs = await res.json();
            const html = logs.length ? logs.map(log => {
                const isErr = log.status >= 400;
                const time = new Date(log.time).toLocaleTimeString();
                return \`<div class="log-item \${isErr ? 'error' : ''}">
                    <span class="log-time">\${time}</span>
                    <span class="log-status \${isErr ? 'err' : 'ok'}">[\${log.status}]</span>
                    <span class="log-model">\${log.provider || ''}/\${log.model || '-'}</span>
                    <span style="color:#888;">\${log.ip}</span>
                    \${log.usage ? \`<span style="color:#888;">(\${log.usage.total_tokens} \${l.tokens})</span>\` : ''}
                    \${log.duration ? \`<span style="color:#888;">\${log.duration}ms</span>\` : ''}
                    \${log.stream ? '<span style="color:#888;">⚡</span>' : ''}
                    \${log.error ? \`<div class="log-error">❌ \${log.error}</div>\` : ''}
                </div>\`;
            }).join('') : '<p style="color:#888;">' + l.noLogs + '</p>';
            document.getElementById('logList').innerHTML = html;
        }
        
        function showMsg(text, type) {
            const el = document.getElementById('msg');
            el.textContent = text;
            el.className = 'message ' + type;
            setTimeout(() => el.className = 'message', 3000);
        }
        
        loadConfig();
        updateUI();
        setInterval(loadLogs, 10000);
    </script>
</body></html>`;
}

// 启动服务器
function startServer() {
    const port = config.port || 1180;
    let server;
    let protocol = 'http';
    
    if (config.ssl?.enabled) {
        // 优先使用本地路径，其次使用上传的文件
        const certPath = config.ssl.certPath || path.join(SSL_DIR, config.ssl.cert || 'server.crt');
        const keyPath = config.ssl.keyPath || path.join(SSL_DIR, config.ssl.key || 'server.key');
        
        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            try {
                const options = {
                    cert: fs.readFileSync(certPath),
                    key: fs.readFileSync(keyPath)
                };
                server = https.createServer(options, app);
                protocol = 'https';
                console.log(`SSL 证书加载自: ${certPath}`);
            } catch (e) {
                console.error('SSL 证书加载失败:', e.message);
                console.log('回退到 HTTP 模式');
                server = http.createServer(app);
            }
        } else {
            console.error('SSL 证书文件不存在，回退到 HTTP 模式');
            server = http.createServer(app);
        }
    } else {
        server = http.createServer(app);
    }
    
    server.listen(port, '0.0.0.0', () => {
        console.log(`
╔═══════════════════════════════════════════════════════╗
║            🤖 LLM Proxy Server v2.1                   ║
╠═══════════════════════════════════════════════════════╣
║  控制台:    ${protocol}://localhost:${port.toString().padEnd(24)}║
║  API:       ${protocol}://localhost:${port}/v1${' '.repeat(21 - port.toString().length)}║
║  协议:      ${protocol.toUpperCase().padEnd(43)}║
║  默认密码:  ${config.password.padEnd(43)}║
╠═══════════════════════════════════════════════════════╣
║  命令接口:                                            ║
║  GET /proxy/providers     - 列出所有 providers        ║
║  GET /proxy/provider/:id  - 切换 provider             ║
║  GET /proxy/status        - 当前状态                  ║
╚═══════════════════════════════════════════════════════╝
        `);
    });
}

startServer();
