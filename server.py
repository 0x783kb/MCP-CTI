import asyncio
import httpx
import os
import logging
from typing import List, Dict, Any, Union
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading
import uuid
import time
import json

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# 导入插件模块
from providers import virustotal, local_whois, rdap, crtsh, fingerprint, portscan, otx, ipinfo, icp, abuseipdb, fofa, threatfox, ssl_info
from providers.base import format_result, validate_ip_address, validate_domain_name
from utils.cache import TTLCache
from config import CACHE_ENABLED, CACHE_TTL

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 加载环境变量
load_dotenv()

# 初始化缓存
global_cache = TTLCache(default_ttl=CACHE_TTL) if CACHE_ENABLED else None
if CACHE_ENABLED:
    logger.info(f"本地缓存已启用 (TTL: {CACHE_TTL}s)")

# 初始化 Server
mcp = FastMCP("CTI-Aggregator")


def _defang_ioc(text: str) -> str:
    """
    对 IOC (IP/Domain/URL) 进行去毒处理，防止误点击。
    Example: 1.1.1.1 -> 1.1.1[.]1, http://bad.com -> hxxp://bad[.]com
    """
    if not text:
        return ""
    # 替换 http/https
    text = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # 替换点 . -> [.] (可选，目前仅替换协议头)
    return text

def _format_timestamp(ts: Any) -> str:
    """将Unix时间戳转换为可读的日期时间字符串"""
    if not isinstance(ts, (int, float)):
        return str(ts)
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(ts)

def _coerce_unix_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


async def execute_provider_queries(client: httpx.AsyncClient, target: str,
                                 query_type: str = "ip") -> List[Dict[str, Any]]:
    """
    执行所有提供商的查询任务。
    """
    tasks = []

    # 为每个提供商创建查询任务
    for provider in [virustotal, local_whois, rdap, crtsh, fingerprint, portscan, otx, ipinfo, icp, abuseipdb, fofa, threatfox, ssl_info]:
        try:
            if query_type == "ip" and hasattr(provider, 'query_ip'):
                tasks.append(provider.query_ip(client, target))
            elif query_type == "domain" and hasattr(provider, 'query_domain'):
                tasks.append(provider.query_domain(client, target))
        except Exception as e:
            logger.error(f"创建 {provider.__name__} 任务失败: {e}")

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    processed_results = []
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"查询任务执行异常: {result}", exc_info=True)
            provider_name = "Unknown"
            if hasattr(result, '__traceback__'):
                tb_info = repr(result.__traceback__)
                if 'virustotal' in tb_info:
                    provider_name = 'VirusTotal'
                elif 'threatminer' in tb_info:
                    provider_name = 'ThreatMiner'
            processed_results.append(format_result(provider_name, error=str(result)))
        else:
            processed_results.append(result)

    return processed_results


def generate_report(target: str, results: List[Dict[str, Any]], report_type: str = "ip") -> str:
    """
    生成固定格式的威胁情报报告，采用分阶段业务流结构 (Step 1-4)。
    """
    # 1. 解析数据
    data_map = {}
    for res in results:
        source = res.get("source", "Unknown")
        if res.get("status") == "success":
            data_map[source] = res.get("data", {})
    
    # 提取关键数据源
    vt_data = data_map.get("VirusTotal", {})
    abuse_data = data_map.get("AbuseIPDB", {})
    ipinfo_data = data_map.get("IPInfo", {})
    icp_data = data_map.get("ICP Filing", {}).get("results", [])
    shodan_data = data_map.get("PortScan", {})
    fofa_data = data_map.get("FOFA", {})
    rdap_data = data_map.get("RDAP", {}) or data_map.get("LocalWhois", {})
    # 补充 VT 的 WHOIS 信息作为 fallback
    if not rdap_data and vt_data:
        rdap_data = {
            "registrar": vt_data.get("registrar"),
            "creation_date": vt_data.get("creation_date"),
            "whois_preview": vt_data.get("whois_preview")
        }
    fp_data = data_map.get("WebFingerprint", {})
    crt_data = data_map.get("crt.sh", {})
    otx_data = data_map.get("AlienVault OTX", {})
    threatfox_data = data_map.get("ThreatFox", {})
    ssl_jarm_data = data_map.get("SSL/JARM", {})

    # --- 报告开始 ---
    title_icon = "🌐" if report_type == "domain" else "🛡️"
    report = [f"# {title_icon} 威胁情报分析报告: {target}", ""]
    
    # --- 🚨 0. 核心预警 (Executive Summary) ---
    # 提取高危特征
    apt_groups = otx_data.get("apt_groups", [])
    is_high_risk = False
    if vt_data and vt_data.get('malicious', 0) > 3:
        is_high_risk = True
        
    findings = []
    if apt_groups:
        findings.append(f"⚠️ 疑似 APT 组织关联: {', '.join(apt_groups)}")
    if is_high_risk:
        findings.append(f"⚠️ 高恶意评分 (VT: {vt_data.get('malicious')})")
    if threatfox_data.get("count", 0) > 0:
        findings.append(f"⚠️ ThreatFox 发现 {threatfox_data.get('count')} 条 IOC 记录")
        
    if findings:
        report.append("## 🚨 0. 核心预警 (Executive Summary)")
        for f in findings:
            report.append(f"- {f}")
        report.append("")
    
    # --- Step 1: 解析阶段 (Resolution) ---
    report.append("## 1️⃣ Step 1: 解析阶段 (Resolution)")
    report.append("> 目标 DNS 解析、历史解析记录与被动 DNS 关联。")
    report.append("")
    
    # 1.1 当前解析
    cur_v4 = []
    cur_v6 = []
    try:
        infos = socket.getaddrinfo(target, None)
        for _, _, _, _, addr in infos:
            ip = addr[0]
            if ":" in ip:
                if ip not in cur_v6: cur_v6.append(ip)
            else:
                if ip not in cur_v4: cur_v4.append(ip)
    except Exception:
        pass

    if report_type == "domain":
        v4_str = ", ".join(cur_v4[:10]) if cur_v4 else "`无`"
        v6_str = ", ".join(cur_v6[:10]) if cur_v6 else "`无`"
        report.append(f"- **当前 DNS 解析**:")
        report.append(f"  - IPv4: {v4_str}")
        report.append(f"  - IPv6: {v6_str}")
    elif report_type == "ip":
        report.append(f"- **IP 地址**: `{target}`")
        # 尝试反向解析
        try:
            hostname = socket.gethostbyaddr(target)[0]
            report.append(f"- **PTR 反向解析**: `{hostname}`")
        except:
            report.append(f"- **PTR 反向解析**: `无`")

    # 1.2 历史/关联解析 (VT)
    if report_type == "domain":
        resolved_ips = vt_data.get("resolved_ips", [])
        hist_ips = [ip.get('ip', ip) if isinstance(ip, dict) else ip for ip in resolved_ips] if resolved_ips else []
        if hist_ips:
            report.append(f"- **历史解析 (VT)**: {', '.join(hist_ips[:10])}")
        else:
            report.append(f"- **历史解析 (VT)**: `暂无数据`")
    elif report_type == "ip":
        resolutions = vt_data.get("resolutions", [])
        if resolutions:
            report.append(f"- **被动 DNS (关联域名)**:")
            for r in resolutions[:5]:
                report.append(f"  - {r.get('last_resolved', '').split()[0]}: `{_defang_ioc(r.get('host_name'))}`")
        else:
            report.append(f"- **被动 DNS**: `暂无数据`")
    report.append("")

    # --- Step 2: 属性阶段 (Attributes) ---
    report.append("## 2️⃣ Step 2: 属性阶段 (Attributes)")
    report.append("> 目标的基础属性、归属地、注册信息与备案情况。")
    report.append("")

    # 2.1 归属地与网络 (IP Only)
    if report_type == "ip" or (report_type == "domain" and cur_v4):
        # 如果是域名，尝试用第一个 IP 展示归属地 (不够准确，但有参考价值)
        # 这里主要展示 IP 报告的归属地
        if report_type == "ip":
            city = ipinfo_data.get("city", "N/A")
            country = ipinfo_data.get("country", "N/A")
            org = ipinfo_data.get("org", "N/A")
            report.append(f"- **地理位置**: {city}, {country}")
            report.append(f"- **ASN / ISP**: {org}")

    # 2.2 ICP 备案 (Domain Only)
    if report_type == "domain":
        if icp_data:
            icp_info = icp_data[0]
            report.append(f"- **ICP 备案**: {icp_info.get('entity_name', 'N/A')} ({icp_info.get('entity_type', 'N/A')}) - {icp_info.get('license', 'N/A')}")
        else:
            report.append(f"- **ICP 备案**: `未备案`")

    # 2.3 WHOIS 信息
    if rdap_data:
        registrar = rdap_data.get('registrar') or '`暂无数据`'
        org_name = rdap_data.get('org') or vt_data.get('whois_preview', '').split('OrgName:')[-1].split('\\n')[0].strip() or '`暂无数据`'
        report.append(f"- **注册商**: {registrar}")
        report.append(f"- **注册组织**: {org_name}")
        
        dates = []
        if rdap_data.get("creation_date"): dates.append(f"创建: {rdap_data.get('creation_date')}")
        if rdap_data.get("expiration_date"): dates.append(f"过期: {rdap_data.get('expiration_date')}")
        if dates:
            report.append(f"- **关键时间**: {'; '.join(dates)}")
        
        emails = rdap_data.get("emails", [])
        if emails:
            email_str = ", ".join(emails) if isinstance(emails, list) else str(emails)
            report.append(f"- **联系邮箱**: {email_str}")
    else:
        report.append("- **WHOIS**: `暂无详细信息`")
    report.append("")

    # --- Step 3: 威胁阶段 (Threat) ---
    report.append("## 3️⃣ Step 3: 威胁阶段 (Threat)")
    report.append("> 多源威胁情报聚合，包括信誉评分、恶意样本关联与家族标记。")
    report.append("")

    # 3.1 信誉评分
    if vt_data:
        malicious = vt_data.get('malicious', 0)
        total = malicious + vt_data.get('harmless', 0) + vt_data.get('suspicious', 0) + vt_data.get('undetected', 0)
        vt_score = f"{malicious}/{total}"
        vt_icon = "🔴" if malicious > 0 else "🟢"
    else:
        vt_score = "`暂无数据`"
        vt_icon = "⚪"
    
    report.append(f"- **VirusTotal**: {vt_icon} {vt_score}")
    
    if report_type == "ip":
        abuse_score = f"{abuse_data.get('score')}%" if abuse_data.get('score') is not None else "`暂无数据`"
        abuse_icon = "🔴" if abuse_data.get('score', 0) > 0 else "🟢"
        report.append(f"- **AbuseIPDB**: {abuse_icon} 置信度 {abuse_score}")

    # 3.2 威胁情报 (OTX / ThreatFox)
    pulses = otx_data.get("pulses", [])
    if pulses:
        report.append(f"- **OTX 情报**: 关联 {len(pulses)} 条情报")
        for p in pulses[:3]:
            report.append(f"  - {p.get('name')}")
            
    tf_count = threatfox_data.get("count")
    if isinstance(tf_count, int) and tf_count > 0:
        report.append(f"- **ThreatFox**: 关联 {tf_count} 条 IOC")
        families = threatfox_data.get("malware_families") or []
        if families:
            report.append(f"  - 涉及家族: {', '.join(families)}")

    # 3.3 关联样本 (Communicating Files)
    samples = vt_data.get("communicating_files", []) or vt_data.get("related_samples", [])
    if samples:
        report.append(f"- **关联样本**: 发现 {len(samples)} 个")
        # Sort by date
        samples_with_ts = []
        for s in samples:
            ts = _coerce_unix_timestamp(s.get("date") or s.get("creation_date") or 0)
            samples_with_ts.append((ts, s))
        samples_with_ts.sort(key=lambda x: x[0], reverse=True)
        
        for ts, s in samples_with_ts[:3]:
            name = s.get("name") or "N/A"
            date_str = _format_timestamp(ts) if ts else "N/A"
            hv = s.get("md5") or s.get("sha256") or s.get("sha1") or "N/A"
            report.append(f"  - [{date_str}] `{hv}` ({name})")
    else:
        report.append(f"- **关联样本**: `未发现`")
    report.append("")

    # --- Step 4: 资产阶段 (Assets) ---
    report.append("## 4️⃣ Step 4: 资产阶段 (Assets)")
    report.append("> 暴露在互联网上的端口、服务、站点指纹与数字证书。")
    report.append("")

    # 4.1 端口与服务
    open_ports = shodan_data.get("open_ports", [])
    fofa_assets = fofa_data.get("assets", [])
    
    if open_ports:
        report.append(f"### Shodan ({len(open_ports)} 端口)")
        for p in open_ports[:10]:
             report.append(f"- **{p.get('port')}**: {p.get('service', 'Unknown')} {p.get('product', '')} {p.get('version', '')}")
    
    if fofa_assets:
        report.append(f"### FOFA ({len(fofa_assets)} 资产)")
        for asset in fofa_assets[:5]:
            port = asset.get('port')
            proto = asset.get('protocol')
            title = asset.get('title', '').strip() or 'N/A'
            link = asset.get('link')
            report.append(f"- **{port}/{proto}**: [{title}]({link})")
    
    if not open_ports and not fofa_assets:
        report.append("- `未检测到明显开放端口或服务`")

    # 4.2 Web 指纹
    if fp_data:
        report.append(f"### Web 指纹")
        headers = fp_data.get('headers', {})
        if headers:
            report.append(f"- **Server**: {headers.get('Server', 'N/A')}")
            report.append(f"- **Powered-By**: {headers.get('X-Powered-By', 'N/A')}")
        if fp_data.get("favicon"):
             report.append(f"- **Favicon**: Hash `{fp_data['favicon'].get('hash')}`")
    
    # 4.3 SSL 证书与 JARM
    report.append(f"### 🔐 SSL 证书与加密")
    
    # 实时 SSL 信息
    ssl_info = ssl_jarm_data.get("ssl", {})
    if ssl_info and ssl_info.get("valid"):
        subject = ssl_info.get("subject", {})
        issuer = ssl_info.get("issuer", {})
        cn = subject.get("commonName", "N/A")
        issuer_cn = issuer.get("commonName", "N/A")
        valid_to = ssl_info.get("notAfter", "N/A")
        
        report.append(f"- **证书主体**: `{cn}`")
        report.append(f"- **颁发机构**: `{issuer_cn}`")
        report.append(f"- **有效期至**: `{valid_to}`")
        
        sans = ssl_info.get("sans", [])
        if sans:
            sans_str = ", ".join(sans[:5]) + ("..." if len(sans) > 5 else "")
            report.append(f"- **SAN 域名**: {sans_str}")
            
        fp = ssl_info.get("fingerprint_sha1")
        if fp:
            report.append(f"- **指纹 (SHA1)**: `{fp}`")
    else:
        if ssl_info.get("error"):
            report.append(f"- **SSL 探测失败**: {ssl_info.get('error')}")

    # JARM 指纹
    jarm_info = ssl_jarm_data.get("jarm", {})
    if jarm_info:
        if jarm_info.get("status") == "success":
            report.append(f"- **JARM 指纹**: `{jarm_info.get('raw')}`")
        elif jarm_info.get("status") == "missing":
            report.append(f"- **JARM**: `未安装 jarm 工具`")
        else:
            report.append(f"- **JARM**: 探测失败 ({jarm_info.get('error')})")
    
    shodan_jarm = shodan_data.get("jarm_fingerprints", [])
    if shodan_jarm:
        report.append(f"- **Shodan JARM**: {', '.join(shodan_jarm[:3])}" + (" ..." if len(shodan_jarm) > 3 else ""))
    
    fofa_jarm_set = set()
    for a in fofa_data.get("assets", [])[:20]:
        j = a.get("jarm")
        if isinstance(j, str) and j:
            fofa_jarm_set.add(j)
    if fofa_jarm_set:
        fofa_jarm_list = list(fofa_jarm_set)
        report.append(f"- **FOFA JARM**: {', '.join(fofa_jarm_list[:3])}" + (" ..." if len(fofa_jarm_list) > 3 else ""))

    # 4.4 历史证书 (crt.sh) - 仅域名模式
    if report_type == "domain":
        certs = crt_data if isinstance(crt_data, list) else crt_data.get("subdomains", [])
        if certs:
            report.append(f"#### 📜 证书历史 (crt.sh)")
            if isinstance(certs[0], dict):
                 for cert in certs[:3]:
                    issued = cert.get('issued_date', '').split('T')[0]
                    cn = cert.get('common_name', 'N/A')
                    report.append(f"- [{issued}] **{cn}**")
            else:
                 report.append(f"- {', '.join(certs[:5])}...")

    return "\n".join(report)


@mcp.tool()
async def investigate_ip(ip: str) -> str:
    """
    [多源聚合] 调查 IP 地址。
    查询 VirusTotal 信誉、关联样本、Shodan/FOFA 端口、AlienVault OTX 情报。
    返回 Markdown 格式的聚合报告。
    """
    logger.info(f"开始调查 IP 地址: {ip}")
    
    # 检查缓存
    if global_cache:
        cache_key = f"report_ip_{ip}"
        cached_report = await global_cache.get(cache_key)
        if cached_report:
            logger.info(f"命中缓存: {ip}")
            return cached_report

    try:
        # 增加超时时间以适应大量关联数据的查询
        async with httpx.AsyncClient(timeout=60.0) as client:
            results = await execute_provider_queries(client, ip, "ip")
            report = generate_report(ip, results, "ip")
            
            # 写入缓存
            if global_cache:
                await global_cache.set(cache_key, report)
                
            logger.info(f"IP 地址 {ip} 调查完成")
            return report
    except Exception as e:
        logger.error(f"调查 IP 地址 {ip} 失败: {e}", exc_info=True)
        return f"# ❌ 调查失败\n\n错误信息: {str(e)}"


@mcp.tool()
async def investigate_domain(domain: str) -> str:
    """
    [多源聚合] 调查域名。
    执行四步分析法：1.解析(DNS/历史) -> 2.属性(Whois/备案) -> 3.威胁(信誉/样本) -> 4.资产(指纹/证书)。
    """
    logger.info(f"开始调查域名: {domain}")
    
    # 检查缓存
    if global_cache:
        cache_key = f"report_domain_{domain}"
        cached_report = await global_cache.get(cache_key)
        if cached_report:
            logger.info(f"命中缓存: {domain}")
            return cached_report

    try:
        # 增加超时时间以适应大量关联数据的查询
        async with httpx.AsyncClient(timeout=60.0) as client:
            results = await execute_provider_queries(client, domain, "domain")
            vt_ips: List[str] = []
            try:
                for r in results:
                    if r.get("source") == "VirusTotal" and r.get("status") == "success":
                        data = r.get("data", {})
                        resolved = data.get("resolved_ips", [])
                        vt_ips = [ip.get("ip", ip) if isinstance(ip, dict) else ip for ip in resolved]
                        break
            except Exception:
                vt_ips = []
            if not vt_ips:
                try:
                    _, _, addr_list = socket.gethostbyname_ex(domain)
                    vt_ips = list(dict.fromkeys(addr_list))
                except Exception:
                    vt_ips = []
            if vt_ips:
                try:
                    ps = await portscan.query_ip(client, vt_ips[0])
                    results.append(ps)
                except Exception as e:
                    logger.warning(f"端口扫描失败: {e}")
            report = generate_report(domain, results, "domain")
            
            # 写入缓存
            if global_cache:
                await global_cache.set(cache_key, report)
                
            logger.info(f"域名 {domain} 调查完成")
            return report
    except Exception as e:
        logger.error(f"调查域名 {domain} 失败: {e}", exc_info=True)
        return f"# ❌ 域名调查失败\n\n错误信息: {str(e)}"


@mcp.tool()
async def investigate_batch(targets: List[str]) -> str:
    """
    [批量分析] 自动识别 IP 或域名并并行调查。
    输入示例: ["1.1.1.1", "baidu.com"] 或 "1.1.1.1, baidu.com" (如果是字符串会自动分割)
    返回合并的简报和详细报告链接。
    """
    # 处理字符串输入 (如果用户传入逗号分隔字符串)
    final_targets = []
    if isinstance(targets, str):
        # 替换中文逗号
        targets = targets.replace("，", ",")
        final_targets = [t.strip() for t in targets.split(",") if t.strip()]
    else:
        final_targets = targets

    if not final_targets:
        return "❌ 请提供至少一个 IP 或域名"

    if len(final_targets) > 20:
        return "⚠️ 批量查询限制最多 20 个目标，请分批进行。"

    logger.info(f"开始批量调查: {final_targets}")
    
    # 并发控制
    semaphore = asyncio.Semaphore(5) # 最多5个并发目标
    
    async def limited_investigate(target: str):
        async with semaphore:
            async with httpx.AsyncClient(timeout=60.0) as client:
                query_type = "ip" if validate_ip_address(target) else "domain"
                if query_type == "domain" and not validate_domain_name(target):
                    return {"target": target, "error": "Invalid Format", "report": ""}
                
                results = await execute_provider_queries(client, target, query_type)
                report = generate_report(target, results, query_type)
                return {"target": target, "type": query_type, "results": results, "report": report}

    # 执行任务
    tasks = [limited_investigate(t) for t in final_targets]
    batch_results = await asyncio.gather(*tasks)

    # 生成汇总报告
    summary_report = ["# 📊 Batch Analysis Summary", "", "| Target | Type | Risk Score (VT) | Key Findings |", "| :--- | :--- | :--- | :--- |"]
    
    detailed_reports = []

    for res in batch_results:
        target = res.get("target")
        if "error" in res:
            summary_report.append(f"| {target} | N/A | N/A | ❌ {res['error']} |")
            continue
            
        # 提取关键信息用于汇总
        # 简单的提取 VT 分数
        vt_score = "N/A"
        key_findings = []
        
        # 解析 results 来获取摘要
        for r in res.get("results", []):
            if r.get("source") == "VirusTotal" and r.get("status") == "success":
                data = r.get("data", {})
                vt_score = f"{data.get('malicious', 0)}/{data.get('malicious', 0) + data.get('harmless', 0)}"
            
            if r.get("source") == "AbuseIPDB" and r.get("status") == "success":
                 score = r.get("data", {}).get("abuseConfidenceScore")
                 if score and score > 0:
                     key_findings.append(f"Abuse:{score}%")
            
            if r.get("source") == "PortScan (Shodan)" and r.get("status") == "success":
                 ports = r.get("data", {}).get("open_ports", [])
                 if ports:
                     key_findings.append(f"Ports:{len(ports)}")
        
        findings_str = ", ".join(key_findings) or "No critical findings"
        summary_report.append(f"| {target} | {res.get('type')} | {vt_score} | {findings_str} |")
        
        detailed_reports.append(res.get("report"))

    final_output = "\n".join(summary_report) + "\n\n---\n\n" + "\n\n---\n\n".join(detailed_reports)
    return final_output


@mcp.tool()
async def health_check() -> str:
    """
    检查系统健康状态，包括环境变量和提供商配置。
    """
    status = ["# 🔧 系统健康检查", "---"]
    vt_key = os.getenv("VT_API_KEY")
    if vt_key:
        status.append("- ✅ **VirusTotal API密钥**: 已配置")
    else:
        status.append("- ⚠️ **VirusTotal API密钥**: 未配置 (VirusTotal查询将受限)")
    
    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key:
        status.append("- ✅ **Shodan API密钥**: 已配置 (使用完整 API)")
    else:
        status.append("- ℹ️ **Shodan API密钥**: 未配置 (使用免费 InternetDB)")

    fofa_email = os.getenv("FOFA_EMAIL")
    fofa_key = os.getenv("FOFA_API_KEY")
    if fofa_email and fofa_key:
        status.append("- ✅ **FOFA API配置**: 已配置")
    else:
        status.append("- ⚠️ **FOFA API配置**: 未配置 (需同时配置 EMAIL 和 KEY)")

    status.append("\n### 活跃提供商")
    status.append("- ✅ VirusTotal")
    status.append("- ✅ LocalWhois")
    status.append("- ✅ RDAP (Registration Data)")
    status.append("- ✅ crt.sh (Certificate History)")
    status.append("- ✅ WebFingerprint (Headers/Favicon)")
    if shodan_key:
        status.append("- ✅ PortScan (Shodan API)")
    else:
        status.append("- ✅ PortScan (Shodan InternetDB)")
    status.append("- ✅ AlienVault OTX (Threat Intelligence)")
    status.append("- ✅ IPInfo (Geolocation & Privacy)")
    status.append("- ✅ ICP Filing (beianx.cn)")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        status.append("- ✅ AbuseIPDB (Reputation & Reports)")
    else:
        status.append("- ⚠️ AbuseIPDB (Not Configured)")

    if fofa_email and fofa_key:
        status.append("- ✅ FOFA (Cyberspace Search)")
    else:
        status.append("- ⚠️ FOFA (Not Configured)")

    return "\n".join(status)


@mcp.tool()
async def resolve_domain_ips(domain: str) -> str:
    if not validate_domain_name(domain):
        return "❌ 输入域名无效"
    ipv4 = []
    ipv6 = []
    try:
        infos = socket.getaddrinfo(domain, None)
        for family, _, _, _, addr in infos:
            ip = addr[0]
            if ":" in ip:
                if ip not in ipv6:
                    ipv6.append(ip)
            else:
                if ip not in ipv4:
                    ipv4.append(ip)
    except Exception as e:
        return f"# 🌐 当前解析 IP: {domain}\n\n- IPv4: `无`\n- IPv6: `无`\n\n错误: {str(e)}"
    ipv4_str = ", ".join(ipv4) if ipv4 else "`无`"
    ipv6_str = ", ".join(ipv6) if ipv6 else "`无`"
    return f"# 🌐 当前解析 IP: {domain}\n\n- IPv4: {ipv4_str}\n- IPv6: {ipv6_str}"


if __name__ == "__main__":
    web_mode = os.getenv("WEB_SERVER", "0") == "1"
    if web_mode:
        host = os.getenv("WEB_HOST", "127.0.0.1")
        port = int(os.getenv("WEB_PORT", "8000"))

        JOBS: Dict[str, Dict[str, Any]] = {}

        class WebHandler(BaseHTTPRequestHandler):
            def _send_html(self, content: str, status: int = 200):
                data = content.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            
            def _send_json(self, obj: Any, status: int = 200):
                data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                try:
                    url = urlparse(self.path)
                    if url.path == "/":
                         html = (
                             "<!doctype html><html><head><meta charset='utf-8'><title>MCP CTI</title>"
                            "<style>:root{--bg:#ffffff;--fg:#0f172a;--muted:#6b7280;--primary:#2563eb;--border:#e5e7eb;--card:#f8fafc;--success:#22c55e}@media(prefers-color-scheme:dark){:root{--bg:#0b1220;--fg:#e5e7eb;--muted:#94a3b8;--primary:#60a5fa;--border:#1f2937;--card:#0f172a;--success:#22c55e}}body{font-family:system-ui,Arial,sans-serif;background:var(--bg);color:var(--fg);margin:0}a{color:var(--primary)}.container{max-width:900px;margin:32px auto;padding:0 20px}.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.title{font-size:20px;margin:0 0 8px}.desc{color:var(--muted);margin:0 0 16px}.chips{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}.chip{border:1px solid var(--border);border-radius:999px;padding:6px 10px;font-size:14px;background:transparent;color:var(--fg);cursor:pointer}.chip:hover{border-color:var(--primary)}textarea{width:100%;min-height:140px;border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--bg);color:var(--fg);font-family:ui-monospace,monospace;font-size:14px}button{border:none;border-radius:10px;padding:10px 14px;font-size:14px;cursor:pointer}button.primary{background:var(--primary);color:#fff}button.secondary{background:transparent;color:var(--fg);border:1px solid var(--border)}button:disabled{opacity:.6;cursor:not-allowed}.progress{width:100%;background:var(--border);border-radius:999px;overflow:hidden;height:12px}.bar{height:12px;background:var(--success);width:0%}.stage{font-size:14px;color:var(--muted);margin:8px 0}.toolbar{display:flex;gap:8px;margin:12px 0;flex-wrap:wrap}.result{margin-top:16px}.footer{color:var(--muted);font-size:12px;margin-top:8px}</style>"
                            "</head><body>"
                            "<div class='container'>"
                            "<div class='card'>"
                            "<h3 class='title'>MCP CTI 浏览器查询</h3>"
                            "<p class='desc'>自动识别域名 / IP；支持批量混合（逗号 / 空格 / 换行分隔）。</p>"
                            "<div class='chips'>"
                            "<button class='chip' data-s='1.1.1.1'>1.1.1.1</button>"
                            "<button class='chip' data-s='www.yyward.com'>www.yyward.com</button>"
                            "<button class='chip' data-s='8.8.8.8, example.com'>8.8.8.8, example.com</button>"
                            "</div>"
                            "<textarea id='input' placeholder='输入多个目标，每行一个或用逗号 / 空格分隔'></textarea>"
                            "<div class='toolbar'>"
                            "<button id='start' class='primary'>开始查询</button>"
                            "<button id='clear' class='secondary'>清空</button>"
                            "<button id='dl-md' class='secondary' disabled>导出 Markdown</button>"
                            "<button id='dl-html' class='secondary' disabled>导出 HTML</button>"
                            "</div>"
                            "<div class='progress'><div id='bar' class='bar'></div></div>"
                            "<div id='stage' class='stage'></div>"
                            "<div id='result' class='result'></div>"
                            "<div class='footer'>API: /investigate_ip, /investigate_domain, /investigate_batch, /submit, /task_status, /task_result, /resolve</div>"
                            "</div>"
                            "</div>"
                            "<script src='https://cdn.jsdelivr.net/npm/marked/marked.min.js'></script>"
                            "<script>"
                            "const startBtn=document.getElementById('start');const clearBtn=document.getElementById('clear');const dlMd=document.getElementById('dl-md');const dlHtml=document.getElementById('dl-html');const input=document.getElementById('input');const bar=document.getElementById('bar');const stageEl=document.getElementById('stage');const resultEl=document.getElementById('result');const chips=document.querySelectorAll('.chip');let jobId=null;let lastReport='';"
                            "chips.forEach(c=>c.addEventListener('click',()=>{const s=c.getAttribute('data-s');if(!input.value.trim())input.value=s;else input.value+='\\n'+s;}));"
                            "function setProgress(p){bar.style.width=(p||0)+'%';}"
                            "function setStage(t){stageEl.textContent=t||'';}"
                            "function enableExport(en){dlMd.disabled=!en;dlHtml.disabled=!en;}"
                            "function setBusy(b){startBtn.disabled=b;clearBtn.disabled=b;}"
                            "clearBtn.onclick=()=>{if(startBtn.disabled)return;input.value='';resultEl.innerHTML='';setProgress(0);setStage('');enableExport(false);};"
                            "dlMd.onclick=()=>{const blob=new Blob([lastReport],{type:'text/markdown'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='report.md';a.click();};"
                            "dlHtml.onclick=()=>{const html='<!doctype html><html><head><meta charset=\"utf-8\"><title>CTI Report</title><style>body{font-family:system-ui,Arial,sans-serif;margin:24px}h1,h2,h3{margin-top:1em}</style></head><body>'+marked.parse(lastReport)+'</body></html>';const blob=new Blob([html],{type:'text/html'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='report.html';a.click();};"
                            "startBtn.onclick=async()=>{enableExport(false);resultEl.innerHTML='';setProgress(0);setStage('提交任务中...');setBusy(true);const q=input.value.trim();if(!q){alert('请输入内容');setBusy(false);return;}const form=new URLSearchParams();form.set('q',q);const resp=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:form.toString()});const data=await resp.json();jobId=data.job_id;setStage('已提交，开始查询...');const poll=async()=>{const s=await fetch('/task_status?job_id='+jobId);const info=await s.json();setProgress(info.progress||0);setStage(info.stage||info.status);if(info.status==='done'){const r=await fetch('/task_result?job_id='+jobId);const txt=await r.text();lastReport=txt;resultEl.innerHTML=marked.parse(txt);enableExport(true);setBusy(false);window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'});}else if(info.status==='error'){resultEl.textContent='任务失败';setBusy(false);}else{setTimeout(poll,900);} };poll();};"
                            "</script>"
                            "</body></html>"
                         )
                         self._send_html(html)
                         return

                    params = parse_qs(url.query)
                    if url.path == "/query":
                        q = (params.get("q", [""])[0] or "").strip()
                        if not q:
                            self._send_html("<h3>缺少查询参数</h3>", 400)
                            return
                        raw = q.replace("，", ",")
                        tokens = []
                        for part in raw.replace("\n", " ").split(" "):
                            part = part.strip()
                            if not part:
                                continue
                            if "," in part:
                                tokens.extend([p.strip() for p in part.split(",") if p.strip()])
                            else:
                                tokens.append(part)
                        unique_targets = []
                        for t in tokens:
                            if t not in unique_targets:
                                unique_targets.append(t)

                        if len(unique_targets) > 1:
                            report = asyncio.run(investigate_batch(", ".join(unique_targets)))
                        else:
                            target = unique_targets[0]
                            if validate_ip_address(target):
                                report = asyncio.run(investigate_ip(target))
                            elif validate_domain_name(target):
                                report = asyncio.run(investigate_domain(target))
                            else:
                                self._send_html("<h3>输入格式不正确：请提供有效的域名或 IP</h3>", 400)
                                return
                        html = (
                            "<!doctype html><html><head><meta charset='utf-8'><title>查询结果</title>"
                            "<style>body{font-family:system-ui,Arial,sans-serif;margin:24px}a{color:#0366d6;text-decoration:none}pre{white-space:pre-wrap;background:#f6f8fa;padding:16px;border-radius:8px;border:1px solid #eaecef}</style>"
                            "</head><body>"
                            f"<p><a href='/'>返回</a></p>"
                            f"<div id='md'></div>"
                            "<script src='https://cdn.jsdelivr.net/npm/marked/marked.min.js'></script>"
                            "<script>document.getElementById('md').innerHTML=marked.parse(" + json.dumps(report) + ");</script>"
                            "</body></html>"
                        )
                        self._send_html(html)
                        return

                    if url.path == "/investigate_ip":
                        ip = (params.get("ip", [""])[0] or "").strip()
                        if not ip:
                            self._send_html("缺少 ip 参数", 400)
                            return
                        report = asyncio.run(investigate_ip(ip))
                        self._send_html(f"<pre>{report}</pre>")
                        return

                    if url.path == "/investigate_domain":
                        domain = (params.get("domain", [""])[0] or "").strip()
                        if not domain:
                            self._send_html("缺少 domain 参数", 400)
                            return
                        report = asyncio.run(investigate_domain(domain))
                        self._send_html(f"<pre>{report}</pre>")
                        return
                    
                    if url.path == "/resolve":
                        domain = (params.get("domain", [""])[0] or "").strip()
                        if not domain:
                            self._send_html("缺少 domain 参数", 400)
                            return
                        report = asyncio.run(resolve_domain_ips(domain))
                        self._send_html(f"<pre>{report}</pre>")
                        return
                    
                    if url.path == "/investigate_batch":
                        targets = (params.get("targets", [""])[0] or "").strip()
                        if not targets:
                            self._send_html("缺少 targets 参数", 400)
                            return
                        report = asyncio.run(investigate_batch(targets))
                        self._send_html(f"<pre>{report}</pre>")
                        return

                    if url.path == "/task_status":
                        job_id = (params.get("job_id", [""])[0] or "").strip()
                        if not job_id or job_id not in JOBS:
                            self._send_json({"error": "job not found"}, 404)
                            return
                        self._send_json({
                            "status": JOBS[job_id].get("status"),
                            "stage": JOBS[job_id].get("stage"),
                            "progress": JOBS[job_id].get("progress", 0)
                        })
                        return

                    if url.path == "/task_result":
                        job_id = (params.get("job_id", [""])[0] or "").strip()
                        if not job_id or job_id not in JOBS:
                            self._send_html("job not found", 404)
                            return
                        rep = JOBS[job_id].get("report", "")
                        self._send_html(rep if rep else "no report", 200)
                        return

                    self._send_html("Not Found", 404)
                except Exception as e:
                    logger.error(f"Web handler error: {e}", exc_info=True)
                    self._send_html("Internal Server Error", 500)
            
            def do_POST(self):
                try:
                    url = urlparse(self.path)
                    length = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
                    params = parse_qs(body)
                    if url.path == "/submit":
                        q = (params.get("q", [""])[0] or "").strip()
                        if not q:
                            self._send_json({"error": "missing q"}, 400)
                            return
                        raw = q.replace("，", ",")
                        tokens = []
                        for part in raw.replace("\n", " ").split(" "):
                            part = part.strip()
                            if not part:
                                continue
                            if "," in part:
                                tokens.extend([p.strip() for p in part.split(",") if p.strip()])
                            else:
                                tokens.append(part)
                        unique_targets = []
                        for t in tokens:
                            if t not in unique_targets:
                                unique_targets.append(t)
                        job_id = uuid.uuid4().hex
                        JOBS[job_id] = {"status": "queued", "stage": "queued", "progress": 0, "report": ""}
                        def run_job():
                            try:
                                JOBS[job_id]["status"] = "running"
                                JOBS[job_id]["stage"] = "解析并准备查询"
                                JOBS[job_id]["progress"] = 10
                                time.sleep(0.2)
                                JOBS[job_id]["stage"] = "执行查询"
                                JOBS[job_id]["progress"] = 40
                                if len(unique_targets) > 1:
                                    report = asyncio.run(investigate_batch(", ".join(unique_targets)))
                                else:
                                    target = unique_targets[0]
                                    if validate_ip_address(target):
                                        report = asyncio.run(investigate_ip(target))
                                    else:
                                        report = asyncio.run(investigate_domain(target))
                                JOBS[job_id]["stage"] = "生成报告"
                                JOBS[job_id]["progress"] = 80
                                time.sleep(0.2)
                                JOBS[job_id]["report"] = report
                                JOBS[job_id]["stage"] = "完成"
                                JOBS[job_id]["progress"] = 100
                                JOBS[job_id]["status"] = "done"
                            except Exception as e:
                                logger.error(f"Job {job_id} failed: {e}", exc_info=True)
                                JOBS[job_id]["status"] = "error"
                                JOBS[job_id]["stage"] = "error"
                                JOBS[job_id]["progress"] = 100
                        threading.Thread(target=run_job, daemon=True).start()
                        self._send_json({"job_id": job_id})
                        return
                    self._send_json({"error": "Not Found"}, 404)
                except Exception as e:
                    logger.error(f"Web handler POST error: {e}", exc_info=True)
                    self._send_json({"error": "Internal Server Error"}, 500)

        httpd = HTTPServer((host, port), WebHandler)
        logger.info(f"Web 服务器已启动: http://{host}:{port}/")
        print(f"Preview URL: http://{host}:{port}/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
    else:
        logger.info("启动 CTI-Aggregator MCP 服务器")
        mcp.run()
