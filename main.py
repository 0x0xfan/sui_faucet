#作者：阿凡    
#推特：https://x.com/Sync_aFan
import requests
from typing import Dict, Any, Optional, Tuple, List
import time
import random
import string
import os
from tools.log_settings.log import logger

def get_jwt_token():
    """获取JWT token的函数"""
    url = "https://faucet.n1stake.com/api/auth"
    
    headers = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "cookie": "",
        "priority": "u=1, i",
        "referer": "https://faucet.n1stake.com/",
        "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            # 解析JSON响应
            response_json = response.json()
            # 获取token值
            token = response_json.get("token")
            if token:
                logger.info("成功获取JWT token")
                return token
            else:
                logger.error("响应中没有找到token")
                return None
        else:
            logger.error(f"获取token失败，状态码: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"获取token时发生错误: {e}")
        return None

# 代理管理
class ProxyManager:
    def __init__(self, proxy_file: str = "proxy1.txt"):
        self.proxy_file = proxy_file
        self.proxies = self._load_proxies()
        self.current_index = 0
        self.failed_proxies = set()  # 记录失败的代理
        
    def _load_proxies(self) -> List[str]:
        """从文件加载代理列表"""
        try:
            with open(self.proxy_file, 'r', encoding='utf-8') as f:
                proxies = [line.strip() for line in f if line.strip()]
            logger.info(f"成功加载 {len(proxies)} 个代理")
            return proxies
        except Exception as e:
            logger.error(f"加载代理文件失败: {str(e)}")
            return []
            
    def get_next_proxy(self) -> Dict[str, str]:
        """获取下一个可用的代理"""
        if not self.proxies:
            logger.error("没有可用的代理")
            return {}
            
        # 尝试获取下一个可用代理
        max_attempts = len(self.proxies)
        for _ in range(max_attempts):
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            
            # 如果代理不在失败列表中，则使用
            if proxy not in self.failed_proxies:
                return {
                    "http": f"http://{proxy}",
                    "https": f"http://{proxy}"
                }
            
        # 如果所有代理都失败，清空失败列表重试
        logger.warning("所有代理都失败，清空失败列表重试")
        self.failed_proxies.clear()
        return self.get_next_proxy()
        
    def mark_proxy_failed(self, proxy: str):
        """标记代理为失败"""
        self.failed_proxies.add(proxy)
        logger.warning(f"代理 {proxy} 被标记为失败")
        
    def get_current_proxy(self) -> Dict[str, str]:
        """获取当前代理"""
        if not self.proxies:
            return {}
        return self.get_next_proxy()

# 初始化代理管理器
proxy_manager = ProxyManager()

# 全局代理变量
proxy = proxy_manager.get_current_proxy()

def update_global_proxy():
    """更新全局代理"""
    global proxy
    proxy = proxy_manager.get_next_proxy()
    logger.info(f"切换到新代理: {proxy['http']}")

def test_proxy_connection(proxy_dict: Dict[str, str], timeout: int = 5) -> bool:
    """测试代理连接是否可用"""
    try:
        # 先测试ipinfo.io
        response = requests.get("https://ipinfo.io/", proxies=proxy_dict, timeout=timeout)
        if response.status_code == 200:
            ip_info = response.json()
            logger.info(f"当前代理IP: {ip_info['ip']} \t 当前地区: {ip_info.get('region', '未知')}")
            
            # 再测试目标网站
            test_url = "https://faucet.n1stake.com"
            response = requests.get(test_url, proxies=proxy_dict, timeout=timeout)
            if response.status_code == 200:
                logger.info("代理能够正常访问领水网站")
                return True
            else:
                logger.warning(f"代理无法访问目标网站: HTTP {response.status_code}")
                return False
    except Exception as e:
        logger.warning(f"代理连接测试失败: {str(e)}")
    return False

class SuiWallet:
    """
    SUI钱包类
    负责与SUI区块链交互，查询钱包余额等操作
    """
    
    # SUI网络RPC节点URL配置
    RPC_URLS = {
        "testnet": "https://fullnode.testnet.sui.io",  # 测试网节点
        "devnet": "https://fullnode.devnet.sui.io"     # 开发网节点
    }

    def __init__(self, address: str, network: str = "testnet"):
        """
        初始化钱包实例
        
        Args:
            address: SUI钱包地址
            network: 网络类型，默认为测试网(testnet)
        """
        self.address = address
        self.network = network
        # 根据网络类型选择RPC节点，如果指定的网络不存在则使用测试网
        self.rpc_url = self.RPC_URLS.get(network, self.RPC_URLS["testnet"])

    def check_balance(self) -> Tuple[bool, int]:
        """
        查询钱包SUI余额，最多重试3次
        
        Returns:
            Tuple[bool, int]: (是否成功, 余额)
            - 成功返回(True, 余额数值)
            - 失败返回(False, 0)
        """
        max_retries = 3
        base_delay = 2  # 基础重试延迟时间（秒）
        
        for attempt in range(max_retries):
            try:
                # 测试当前代理是否可用
                if not test_proxy_connection(proxy):
                    logger.warning("当前代理不可用，切换到下一个代理")
                    update_global_proxy()
                    continue
                    
                # 构造RPC请求
                response = requests.post(
                    self.rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "suix_getBalance",  # 使用SUI的余额查询方法
                        "params": [self.address, "0x2::sui::SUI"]  # 查询SUI代币余额
                    },
                    proxies=proxy,
                    timeout=3  # 超时时间改为3秒
                )
                
                result = response.json()
                if "error" in result:
                    logger.error(f"查询余额错误: {result['error']}")
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)  # 指数退避
                        logger.warning(f"查询余额失败，{delay}秒后重试...")
                        time.sleep(delay)
                        continue
                    return False, 0
                    
                # 获取余额并转换为整数（SUI的最小单位）
                balance = int(result.get("result", {}).get("totalBalance", "0"))
                # 输出可读性更好的余额信息（1 SUI = 10^9 最小单位）
                logger.info(f"钱包 {self.address} 当前余额: {balance / 1_000_000_000} SUI")
                return True, balance
                
            except requests.exceptions.RequestException as e:
                logger.error(f"查询余额请求异常: {str(e)}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"查询余额失败，{delay}秒后重试...")
                    time.sleep(delay)
                    continue
                return False, 0
            except Exception as e:
                logger.error(f"查询余额未知异常: {str(e)}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"查询余额失败，{delay}秒后重试...")
                    time.sleep(delay)
                    continue
                return False, 0
                
        return False, 0


class SuiFaucet:
    """
    SUI测试币水龙头类
    处理验证码获取和测试币领取的完整流程
    """

    def __init__(self, wallet_addresses: List[str], user_token: str, network: str = "testnet"):
        """
        初始化水龙头实例
        
        Args:
            wallet_addresses: 钱包地址列表
            user_token: nocaptcha服务的用户token
            network: 网络类型，默认为测试网
        """
        # 为每个地址创建钱包实例
        self.wallets = [SuiWallet(addr, network) for addr in wallet_addresses]
        self.user_token = user_token
        self.max_retries = 3  # 最大重试次数
        
        # 生成随机会话ID
        self.session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # nocaptcha验证码服务配置
        self.nocaptcha_config = {
            "sitekey": "d0ba98cc-0528-41a0-98fe-dc66945e5416",
            "referer": "https://faucet.n1stake.com",
            "proxy": proxy["http"].replace("http://", ""),
            "region": "jp",
            "invisible": False,
            "domain": "hcaptcha.com"
        }

    def _get_request_headers(self, include_token: bool = True) -> Dict[str, str]:
        """
        生成请求头
        
        Args:
            include_token: 是否包含User-Token
        
        Returns:
            Dict[str, str]: 请求头字典
        """
        # 获取JWT token
        jwt_token = get_jwt_token()
        if not jwt_token:
            logger.error("获取JWT token失败")
            return {}
            
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": f"Bearer {jwt_token}",  # 添加Bearer前缀
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "DNT": "1",
            "Origin": "https://faucet.n1stake.com",
            "Pragma": "no-cache",
            "Referer": "https://faucet.n1stake.com/",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        # 添加随机请求ID
        headers["X-Request-ID"] = f"{self.session_id}-{random.randint(1000, 9999)}"
        
        if include_token:
            headers["User-Token"] = self.user_token
            
        return headers

    def get_captcha_token(self) -> Optional[str]:
        """获取验证码token"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                headers = self._get_request_headers()
                
                # 测试当前代理是否可用
                if not test_proxy_connection(proxy):
                    logger.warning("当前代理不可用，切换到下一个代理")
                    update_global_proxy()
                    continue
                
                # 添加随机延时，避免请求过快
                time.sleep(random.uniform(1, 3))
                
                # 直接使用全局代理配置
                logger.info(f"使用代理 {proxy['http']} 获取验证码")
                
                # 使用更长的超时时间
                response = requests.post(
                    "http://api.nocaptcha.io/api/wanda/hcaptcha/universal",
                    headers=headers,
                    json=self.nocaptcha_config,
                    proxies=proxy,
                    timeout=50,  # 使用30秒超时
                    verify=True
                )
                
                result = response.json()
                if result.get("status") != 1:
                    error_msg = result.get("msg", "未知错误")
                    logger.error(f"获取验证码失败: {error_msg}")
                    # 如果是识别失败，不标记代理为失败
                    if "识别失败" not in error_msg:
                        proxy_manager.mark_proxy_failed(proxy["http"].replace("http://", ""))
                        update_global_proxy()
                    continue
                    
                token = result.get("data", {}).get("generated_pass_UUID")
                if token:
                    logger.info("成功获取验证码token")
                    return token
                    
                return None
                
            except requests.exceptions.ReadTimeout:
                logger.error("读取超时，切换到下一个代理")
                proxy_manager.mark_proxy_failed(proxy["http"].replace("http://", ""))
                if attempt < max_retries - 1:
                    update_global_proxy()
                    time.sleep(5)  # 增加等待时间
                    continue
                return None
            except requests.exceptions.ConnectTimeout:
                logger.error("连接超时，切换到下一个代理")
                proxy_manager.mark_proxy_failed(proxy["http"].replace("http://", ""))
                if attempt < max_retries - 1:
                    update_global_proxy()
                    time.sleep(5)
                    continue
                return None
            except requests.exceptions.RequestException as e:
                logger.error(f"请求异常: {str(e)}")
                proxy_manager.mark_proxy_failed(proxy["http"].replace("http://", ""))
                if attempt < max_retries - 1:
                    update_global_proxy()
                    time.sleep(5)
                    continue
                return None
            except Exception as e:
                logger.error(f"未知异常: {str(e)}")
                return None

    def request_faucet(self, wallet_address: str, captcha_token: str) -> Tuple[bool, bool]:
        """发送领水请求
        Returns:
            Tuple[bool, bool]: (是否成功, 是否是24小时内已领取)
        """
        try:
            # 添加随机延时，避免请求过快
            time.sleep(random.uniform(1, 3))
            
            headers = self._get_request_headers(include_token=False)
            
            # 构造请求数据
            payload = {
                "address": wallet_address,
                "captchaResponse": captcha_token
            }
            
            # 记录请求信息
            logger.info(f"发送领水请求: {wallet_address}")
            
            # 配置证书验证
            verify = os.getenv('SSL_CERT_FILE', True)
            
            # 实现指数退避重试机制
            max_retries = 5
            base_delay = 60
            for attempt in range(max_retries):
                try:
                    # 测试当前代理是否可用
                    if not test_proxy_connection(proxy):
                        logger.warning("当前代理不可用，切换到下一个代理")
                        update_global_proxy()
                        continue
                        
                    response = requests.post(
                        "https://faucet.n1stake.com/api/faucet",
                        headers=headers,
                        json=payload,
                        proxies=proxy,
                        timeout=30,
                        verify=verify
                    )
                    
                    if response.status_code == 200:
                        logger.info("领水请求发送成功")
                        return True, False
                    elif response.status_code == 429:
                        if "This IP can only make one request every 24 hours" in response.text:
                            logger.warning("当前IP已被限制，切换到下一个代理...")
                            # 标记当前代理为失败
                            proxy_manager.mark_proxy_failed(proxy["http"].replace("http://", ""))
                            update_global_proxy()
                            continue
                        elif "You can only request once every 24 hours" in response.text:
                            logger.info("该地址24小时内领取过，无需再次领取")
                            return True, True
                        logger.error(f"领水请求失败: HTTP {response.text}")
                        continue
                    else:
                        logger.error(f"领水请求失败: HTTP {response.text}")
                        return False, False
                        
                except requests.exceptions.RequestException as e:
                    logger.error(f"请求异常: {str(e)}")
                    # 标记当前代理为失败
                    proxy_manager.mark_proxy_failed(proxy["http"].replace("http://", ""))
                    if attempt < max_retries - 1:
                        update_global_proxy()
                        delay = base_delay * (2 ** attempt)
                        logger.warning(f"请求失败，{delay}秒后重试...")
                        time.sleep(delay)
                        continue
                    return False, False
            
            return False, False
            
        except Exception as e:
            logger.error(f"未知异常: {str(e)}")
            return False, False

    def process_wallet(self, wallet: SuiWallet) -> bool:
        """
        处理单个钱包的完整领水流程
        
        Args:
            wallet: 钱包实例
            
        Returns:
            bool: 领水是否成功
        """
        logger.info(f"********************开始处理钱包: {wallet.address}********************")
        
        # 1. 检查初始余额
        success, initial_balance = wallet.check_balance()
        if not success:
            return False
            
        logger.info(f"初始余额: {initial_balance / 1_000_000_000} SUI")
        
        # 2. 尝试领水（最多重试max_retries次）
        for attempt in range(self.max_retries):
            logger.info(f"第 {attempt + 1} 次尝试领水")
            
            # 2.1 获取验证码并请求领水
            captcha_token = self.get_captcha_token()
            if not captcha_token:
                logger.error("获取验证码失败，等待10秒后重试...")
                time.sleep(10)
                continue
            
            # 2.2 发送领水请求
            faucet_result, is_24h_limit = self.request_faucet(wallet.address, captcha_token)
            if faucet_result:
                if is_24h_limit:
                    logger.info(f"跳过钱包 {wallet.address}，继续处理下一个地址")
                    return True
                    
                # 2.3 等待交易确认（随机5-8秒）
                wait_time = random.uniform(5, 8)
                logger.info(f"等待 {wait_time:.1f} 秒确认交易...")
                time.sleep(wait_time)
                
                # 2.4 检查余额变化
                for check_attempt in range(3):  # 最多检查3次余额
                    success, current_balance = wallet.check_balance()
                    if success and current_balance > initial_balance:
                        increase = (current_balance - initial_balance) / 1_000_000_000
                        logger.info(f"✅领水成功! 余额增加: {increase} SUI")
                        return True
                    elif success:
                        logger.info("余额暂未变化，等待5秒后重新检查...")
                        time.sleep(5)
                    else:
                        logger.error("检查余额失败")
                        break
            
            # 如果这次尝试失败，等待一段时间后重试
            if attempt < self.max_retries - 1:
                wait_time = random.uniform(20, 30)
                logger.info(f"本次尝试未成功，等待 {wait_time:.1f} 秒后重试...")
                time.sleep(wait_time)
        
        logger.warning(f"钱包 {wallet.address} 领水失败，已达到最大重试次数")
        return False

    def run(self):
        """
        执行批量领水主流程
        处理所有钱包的领水请求并输出统计结果
        """
        total_wallets = len(self.wallets)
        logger.info(f"开始执行自动领水，共 {total_wallets} 个钱包")
        
        # 处理每个钱包
        results = []
        start_time = time.time()
        
        for index, wallet in enumerate(self.wallets, 1):
            # 计算进度信息
            progress = f"[{index}/{total_wallets}]"
            logger.info(f"{progress} 开始处理钱包: {wallet.address}")
            
            # 处理钱包
            success = self.process_wallet(wallet)
            results.append((wallet.address, success))
            
            # 计算已用时间和预估剩余时间
            elapsed_time = time.time() - start_time
            avg_time_per_wallet = elapsed_time / index
            remaining_wallets = total_wallets - index
            estimated_remaining_time = avg_time_per_wallet * remaining_wallets
            
            # 输出进度信息
            logger.info(f"{progress} 当前进度: {index}/{total_wallets} ({index/total_wallets*100:.1f}%)")
            logger.info(f"{progress} 已用时间: {elapsed_time/60:.1f}分钟")
            logger.info(f"{progress} 预估剩余时间: {estimated_remaining_time/60:.1f}分钟")
            
            # 处理下一个钱包前等待3秒
            if wallet != self.wallets[-1]:
                time.sleep(3)
        
        # 输出统计结果
        success_count = sum(1 for _, success in results if success)
        logger.info(f"\n领水统计:")
        logger.info(f"总计: {total_wallets} 个")
        logger.info(f"成功: {success_count} 个")
        logger.info(f"失败: {total_wallets - success_count} 个")
        
        # 输出失败的钱包地址
        if failed := [addr for addr, success in results if not success]:
            logger.info(f"\n失败钱包:")
            for addr in failed:
                logger.info(addr)


def main():
    """
    主函数：程序入口
    演示如何使用SuiFaucet类
    """
    # 读取sui领水地址.txt文件,将每行内容作为钱包地址
    with open("地址1.txt", "r") as file:
        wallet_addresses = [line.strip() for line in file.readlines()]
    
    user_token = "你的nocaptcha token"  # 替换为实际的nocaptcha token
    
    # 创建并运行水龙头实例
    faucet = SuiFaucet(wallet_addresses, user_token)
    faucet.run()


if __name__ == "__main__":
    main()

