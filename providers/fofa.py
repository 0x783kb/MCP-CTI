"""
FOFA 模块
提供IP和域名的网络空间资产搜索功能
需要配置 FOFA_EMAIL 和 FOFA_API_KEY
"""
import logging
import base64
from typing import Dict, Any, List
from .base import format_result, validate_ip_address, validate_domain_name
from config import PROVIDER_CONFIG

logger = logging.getLogger(__name__)

# FOFA API URL
FOFA_API_URL = "https://fofa.info/api/v1/search/all"

async def query_ip(client, ip: str) -> Dict[str, Any]:
    """
    使用 FOFA 查询 IP 资产信息
    """
    if not validate_ip_address(ip):
        return format_result("FOFA", error=f"无效的IP地址: {ip}")

    config = PROVIDER_CONFIG.get("fofa", {})
    if not config.get("enabled"):
         return format_result("FOFA", {
            "status": "skipped",
            "message": "FOFA 未启用 (请配置 FOFA_EMAIL 和 FOFA_API_KEY)"
        })

    email = config.get("email")
    key = config.get("api_key")
    
    # 构造查询语句
    query = f'ip="{ip}"'
    qbase64 = base64.b64encode(query.encode()).decode()
    
    params = {
        "email": email,
        "key": key,
        "qbase64": qbase64,
        "fields": "ip,port,protocol,country_name,region_name,city_name,title,server,isp,domain,host,org,icp,os,link",
        "size": 100
    }
    
    try:
        response = await client.get(FOFA_API_URL, params=params, timeout=config.get("timeout", 15))
        
        if response.status_code != 200:
            return format_result("FOFA", error=f"FOFA API 请求失败: {response.status_code}")
            
        data = response.json()
        if data.get("error"):
            return format_result("FOFA", error=f"FOFA API 错误: {data.get('errmsg')}")
            
        results = data.get("results", [])
        
        # 整理返回数据
        assets = []
        for item in results:
            # fields: ip, port, protocol, country, region, city, title, server, isp, domain, host, org, icp, os, link
            # index:  0   1     2         3        4       5     6      7       8    9       10    11   12   13  14
            # 注意：部分字段可能为空或缺少，取决于 API 返回
            # 确保 item 长度足够，或者使用 try-except/get 方式（但 results 是 list of lists）
            # FOFA API 保证返回列表长度与 fields 数量一致
            
            asset = {
                "ip": item[0],
                "port": item[1],
                "protocol": item[2],
                "location": f"{item[3]}/{item[4]}/{item[5]}",
                "title": item[6],
                "server": item[7],
                "isp": item[8],
                "domain": item[9],
                "host": item[10],
                "org": item[11],
                "icp": item[12],
                "os": item[13],
                "link": item[14]
            }
            assets.append(asset)
            
        return format_result("FOFA", {
            "query": query,
            "count": len(assets),
            "assets": assets
        })
        
    except Exception as e:
        logger.error(f"FOFA 查询失败: {e}")
        return format_result("FOFA", error=f"FOFA 查询异常: {str(e)}")

async def query_domain(client, domain: str) -> Dict[str, Any]:
    """
    使用 FOFA 查询域名资产信息
    """
    if not validate_domain_name(domain):
        return format_result("FOFA", error=f"无效的域名: {domain}")

    config = PROVIDER_CONFIG.get("fofa", {})
    if not config.get("enabled"):
         return format_result("FOFA", {
            "status": "skipped",
            "message": "FOFA 未启用 (请配置 FOFA_EMAIL 和 FOFA_API_KEY)"
        })

    email = config.get("email")
    key = config.get("api_key")
    
    # 构造查询语句
    query = f'domain="{domain}"'
    qbase64 = base64.b64encode(query.encode()).decode()
    
    params = {
        "email": email,
        "key": key,
        "qbase64": qbase64,
        "fields": "ip,port,protocol,country_name,region_name,city_name,title,server,isp,domain,host,org,icp,os,link",
        "size": 100
    }
    
    try:
        response = await client.get(FOFA_API_URL, params=params, timeout=config.get("timeout", 15))
        
        if response.status_code != 200:
            return format_result("FOFA", error=f"FOFA API 请求失败: {response.status_code}")
            
        data = response.json()
        if data.get("error"):
            return format_result("FOFA", error=f"FOFA API 错误: {data.get('errmsg')}")
            
        results = data.get("results", [])
        
        assets = []
        for item in results:
            asset = {
                "ip": item[0],
                "port": item[1],
                "protocol": item[2],
                "location": f"{item[3]}/{item[4]}/{item[5]}",
                "title": item[6],
                "server": item[7],
                "isp": item[8],
                "domain": item[9],
                "host": item[10],
                "org": item[11],
                "icp": item[12],
                "os": item[13],
                "link": item[14]
            }
            assets.append(asset)
            
        return format_result("FOFA", {
            "query": query,
            "count": len(assets),
            "assets": assets
        })
        
    except Exception as e:
        logger.error(f"FOFA 查询失败: {e}")
        return format_result("FOFA", error=f"FOFA 查询异常: {str(e)}")
