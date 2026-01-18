# 🛡️ MCP CTI Aggregator

一个基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 的威胁情报聚合服务器。它能够自动查询多个开源情报源（OSINT），为 IP 地址和域名生成全面的安全画像。

## ✨ 核心功能

### 🔍 多源情报聚合
集成 10+个高价值情报源，覆盖 IP 信誉、域名归属、网络资产、基础设施指纹、端口与漏洞等维度：

| 模块 | 功能描述 | 依赖 |
|------|----------|------|
| **VirusTotal** | 恶意评分、关联样本分析、被动 DNS、JARM 指纹 | API Key |
| **AbuseIPDB** | IP 滥用报告统计、置信度评分、攻击类型分布 | API Key |
| **Shodan** | 开放端口扫描、漏洞信息、服务指纹（Banner） | API Key / Free InternetDB |
| **FOFA** | 网络空间资产搜索（域名 / 主机 / 端口 / 指纹） | Email / API Key |
| **ThreatFox** | IOC 匹配与恶意家族关联（abuse.ch） | 无需 Key |
| **AlienVault OTX** | 威胁情报脉冲（Pulses）、APT 组织关联、MITRE ATT&CK 映射 | API Key（Optional） |
| **IPInfo** | 精准 IP 归属地、ASN 信息、隐私检测（VPN / Proxy / Hosting） | API Key（Optional） |
| **ICP Filing** | 中国大陆 ICP 备案查询（beianx.cn） | 无需 Key（内置 Bypass） |
| **WebFingerprint** | 网站指纹识别（HTTP Headers, Favicon Hash） | 无（被动 / 主动可选） |
| **RDAP / Whois** | 域名注册人信息、注册局原始数据 | 无 |
| **crt.sh** | SSL 证书透明度历史记录（子域名挖掘） | 无 |

### 🚀 批量自动化分析
支持批量输入 IP 或域名，并行执行调查任务，自动识别目标类型并生成汇总报告。

## 📦 安装与配置

### 1. 环境准备
确保已安装 Python 3.10+ 和 `uv` (可选但推荐)。

```bash
# 克隆仓库
git https://github.com/0x783kb/MCP-CTI.git
cd mcp-cti

# 创建虚拟环境并安装依赖
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 配置 API Keys
复制 `.env.example` 为 `.env` 并填入您的 API Keys：

```ini
# VirusTotal (必须)
VT_API_KEY=your_vt_api_key

# Shodan (可选，留空则使用 InternetDB)
SHODAN_API_KEY=your_shodan_api_key

# AbuseIPDB (推荐)
ABUSEIPDB_API_KEY=your_abuseipdb_key

# AlienVault OTX (可选)
OTX_API_KEY=your_otx_key

# IPInfo (可选)
IPINFO_API_KEY=your_ipinfo_key

# FOFA（可选，建议配置，需同时提供邮箱与密钥）
FOFA_EMAIL=your_email@example.com
FOFA_API_KEY=your_fofa_api_key
```

## 🚀 快速开始

### 方式一：Web 模式（推荐）
```bash
WEB_SERVER=1 WEB_HOST=127.0.0.1 WEB_PORT=8000 python3 server.py
# 打开浏览器访问 http://127.0.0.1:8000/
```
- 输入域名 / IP（支持批量混合，逗号 / 空格 / 换行分隔）
- 查看进度与渲染后的报告
- 一键导出报告（Markdown / HTML）

### 方式二：MCP 模式（IDE / Agent）
```bash
mcp run server.py
```
- 在兼容 MCP 的 IDE（如 Trae / Cursor）中调用工具进行分析

## 💻 IDE 集成与配置

本服务器支持所有兼容 MCP 协议的客户端。以下是主流 IDE 的配置方法：

### 1. Claude Desktop App
编辑配置文件:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mcp-cti": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/mcp-cti",
        "run",
        "server.py"
      ],
      "env": {
        "VT_API_KEY": "your_key_here",
        "ABUSEIPDB_API_KEY": "your_key_here"
      }
    }
  }
}
```

### 2. Cursor
1. 打开 Cursor 设置面板 (`Cmd + ,` 或 `Ctrl + ,`)。
2. 导航至 **Features** -> **MCP**。
3. 点击 **Add New MCP Server**。
4. 填写配置：
   - **Name**: `mcp-cti`
   - **Type**: `command`
   - **Command**: `uv --directory /absolute/path/to/mcp-cti run server.py`

### 3. Trae IDE
1. 打开设置 (`Cmd + ,`) -> **MCP Servers**。
2. 编辑 JSON 配置文件，添加如下内容：

```json
{
  "mcpServers": {
    "mcp-cti": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/mcp-cti",
        "run",
        "server.py"
      ]
    }
  }
}
```
*注：Trae 会自动加载项目根目录下的 `.env` 文件，无需在 JSON 中重复配置环境变量。*

### 4. Windsurf
编辑配置文件 `~/.codeium/windsurf/mcp_config.json`：

```json
{
  "mcpServers": {
    "mcp-cti": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/mcp-cti",
        "run",
        "server.py"
      ]
    }
  }
}
```

## 🗣️ 提示词指南（Prompt Guide）

配置完成后，您可以在 Chat 中使用自然语言与 MCP 服务器交互。以下是一些高效的提示词示例：

### 🕵️‍♂️ 调查单个目标
> "帮我分析一下 IP 1.1.1.1 的安全性"
> "这个域名 www.baidu.com 是恶意的吗？"
> "调查 1.1.1.1，看看有没有开放端口"

### 📦 批量自动化分析
> "分析以下 IOC 列表：
> 1.1.1.1
> 8.8.8.8
> google.com"

> "我有一批可疑 IP，帮我批量检查一下：192.168.1.1, 10.0.0.1, example.com"

### 🏥 系统健康检查
> "检查一下 MCP 服务器的状态"
> "当前的 API Key 配置都正常吗？"

## 🛠️ 使用指南

### 启动服务器（MCP 模式）
适用于 IDE / Agent 集成与 CLI 调试。

```bash
# 启动 MCP 服务器 (MCP 模式)
mcp run server.py
```

### 启动服务器（Web 模式）
适用于浏览器可视化查询、批量任务与报告导出。

```bash
# 启动 Web 服务器
WEB_SERVER=1 WEB_HOST=127.0.0.1 WEB_PORT=8000 python3 server.py
# 打开浏览器访问
# http://127.0.0.1:8000/
```

### 可用工具（Tools）

- `investigate_ip(ip: str)`: 调查单个 IP 地址，返回详细 Markdown 报告。
- `investigate_domain(domain: str)`: 调查单个域名，返回详细 Markdown 报告。
- `investigate_batch(targets: List[str])`: 批量调查，支持 IP / 域名混合列表，返回汇总表格及详情。
- `health_check()`: 检查系统状态和 API 配置。
- `resolve_domain_ips(domain: str)`: 获取域名当前解析的 IPv4 / IPv6。

### Web 模式功能
- 自动识别域名 / IP，无需手动选择
- 批量混合查询（逗号、空格或换行分隔）
- 前端 Markdown 渲染（基于 marked）
- 任务队列与进度显示（轮询）
- 一键导出报告（Markdown / HTML）
- 展示 FOFA 网络资产（端口 / 服务标题 / 指纹 / 链接）
- 域名报告并列展示解析 IP（历史解析（VT）与当前解析（DNS））

### Web 模式 API
- 单个 IP：`/investigate_ip?ip=1.1.1.1`
- 单个域名：`/investigate_domain?domain=example.com`
- 批量混合（同步）：`/investigate_batch?targets=1.1.1.1, example.com`
- 任务提交（异步）：`POST /submit`（参数 `q` 支持批量混合）
- 任务状态：`GET /task_status?job_id=...`
- 任务结果：`GET /task_result?job_id=...`
- 当前解析：`/resolve?domain=example.com`

## 📊 报告示例

生成的报告严格遵循四步分析法结构：
1.  **🚨 0. Executive Summary**: 核心高危预警（APT 关联、高恶意评分、IOC 命中）。
2.  **1️⃣ Step 1: Resolution**: 域名解析记录（IPv4/v6）、历史解析与被动 DNS。
3.  **2️⃣ Step 2: Attributes**: 基础属性、地理位置、ISP/ASN、Whois 与备案信息。
4.  **3️⃣ Step 3: Threat**: 多源威胁情报聚合（VirusTotal, AbuseIPDB, ThreatFox, OTX）。
5.  **4️⃣ Step 4: Assets**: 网络资产暴露面（端口、服务、站点指纹、证书）。


## 🔒 安全与隐私
- **被动扫描优先**：默认不进行主动漏洞扫描，仅通过被动 API 获取数据。
- **IOC 去毒**：报告中的 URL 和 IP 会自动进行去毒处理（例如 `http://` -> `hxxp://`），防止误触。

## ❓ 常见问题（FAQ）
- 为什么端口与漏洞信息较少？
  - 未配置 Shodan API Key 时，使用 InternetDB（免费版，信息较少）。
- FOFA 没数据或提示未启用？
  - 需同时配置 `FOFA_EMAIL` 与 `FOFA_API_KEY`，否则模块会跳过。
- 域名报告为什么没有网站指纹？
  - 默认关闭主动指纹（OPSEC 保护），需在配置中开启 `fingerprint.active_scan`。
- Web 页面导出按钮不可用？
  - 报告生成完成后才可导出；确保浏览器可访问 marked CDN。
- 为什么“当前解析（DNS）”为空？
  - 域名可能未解析或被暂停；可使用 `/resolve?domain=...` 独立查看并确认错误信息。

## 📝 开发计划
- [x] 集成 VirusTotal, Shodan, Whois
- [x] 集成 ICP 备案查询
- [x] 集成 AbuseIPDB
- [x] 增加批量分析功能
- [x] 支持本地缓存 (Memory/File)
- [x] 增强 APT 归因与高危预警展示
- [x] 集成 ThreatFox（IOC 匹配与家族关联）
- [ ] 增加 C2 识别规则库
- [x] 导出 HTML / Markdown 报告（Web）
