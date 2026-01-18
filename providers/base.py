"""
基础工具模块 - 提供通用的数据格式化和验证功能
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def format_result(source: str, data: dict = None, error: str = None) -> dict:
    """
    统一格式化威胁情报查询结果
    
    Args:
        source: 数据来源名称
        data: 成功时的数据字典
        error: 错误信息（如果有）
    
    Returns:
        统一格式的结果字典
    """
    return {
        "source": source,
        "status": "error" if error else "success",
        "data": data if data else {},
        "error_msg": error
    }


def validate_ip_address(ip: str) -> bool:
    """
    验证IP地址格式
    
    Args:
        ip: 待验证的IP地址
    
    Returns:
        是否有效的IP地址
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logger.warning(f"无效的IP地址格式: {ip}")
        return False


def validate_domain_name(domain: str) -> bool:
    """
    验证域名格式
    
    Args:
        domain: 待验证的域名
    
    Returns:
        是否有效的域名
    """
    import re
    # 简化的域名验证正则表达式
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    if len(domain) > 253:  # 域名最大长度
        logger.warning(f"域名过长: {domain}")
        return False
    
    if not domain_pattern.match(domain):
        logger.warning(f"无效的域名格式: {domain}")
        return False
    
    return True


def sanitize_data(data: Any, max_length: int = 1000) -> Any:
    """
    清理和限制数据大小
    
    Args:
        data: 待清理的数据
        max_length: 最大长度限制
    
    Returns:
        清理后的数据
    """
    if isinstance(data, str):
        if len(data) > max_length:
            logger.warning(f"数据长度超过限制，进行截断: {len(data)} > {max_length}")
            return data[:max_length] + "..."
        return data
    elif isinstance(data, (list, dict)):
        # 对于复杂数据结构，限制元素数量
        if isinstance(data, list) and len(data) > 100:
            logger.warning(f"列表数据元素过多，进行截断: {len(data)} > 100")
            return data[:100]
        return data
    else:
        return data


async def make_request(client, url: str, headers: Dict[str, str] = None, timeout: float = 15.0) -> Any:
    """
    发送通用 HTTP 请求并处理错误
    """
    try:
        resp = await client.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.info(f"资源未找到: {url}")
            return None
        elif resp.status_code == 403:
             logger.warning(f"权限拒绝 (403): {url}")
             return Exception("Permission Denied (Check API Key)")
        elif resp.status_code == 429:
             logger.warning(f"请求被限流 (429): {url}")
             return Exception("Rate Limited")
        else:
            logger.warning(f"请求失败 {resp.status_code}: {url}")
            return Exception(f"HTTP {resp.status_code}")
    except Exception as e:
        logger.error(f"请求异常 {url}: {e}")
        return e