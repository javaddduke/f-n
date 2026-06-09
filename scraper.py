import sys
import subprocess

# ================= 📦 自动依赖检查区 📦 =================
try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

try:
    from tqdm import tqdm
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
    from tqdm import tqdm

import base64
import os
import json
import socket
import time
from datetime import datetime
from urllib.parse import quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= ⚙️ 核心配置区 ⚙️ =================

CUSTOM_REMARK_B64 = "56eR5oqA5YWx5LqrLeW8gOa6kOiKgueCuQ=="

# 最终订阅文件保留的“优质活节点”最大数量
MAX_NODES_LIMIT = 1500 

# 并发测速的线程数（GitHub Actions 盒子性能有限，100-150 是最佳平衡点，既快又不会丢包）
MAX_WORKERS = 120

# 测速超时时间（单位：秒）。超过 3 秒连不上的直接视为死节点淘汰
PING_TIMEOUT = 3.0

SOURCE_URLS = [
    "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
    "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/v202605312",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",
    "https://github.cmliussss.net/https://raw.githubusercontent.com/qmqv/jd07/refs/heads/main/v207-1010.txt",
    "https://ghfast.top/https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://proxy.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://sub.proxygo.org/v2ray.php?key=191c91f624a800e83942463fd667bba5",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://app.sublink.works/x/ZrVEXNV",
    "https://gcore.jsdelivr.net/gh/aews/jd2/v20528.txt",
    "https://mm.mibei77.com/202606/06.0564bacrt.txt",
    "https://mm.mibei77.com/202606/06.0664bacrt.txt",
    "https://mm.mibei77.com/202606/06.0764bacrt.txt",
    "https://mm.mibei77.com/202606/06.0864bacrt.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/trojan.txt",
    "https://gt.1155555.xyz/https://raw.githubusercontent.com/shaoyouvip/free/refs/heads/main/base64.txt" 
]

BLACKLIST_KEYWORDS = ['-1', '127.0.0.1', 'timeout', 'err', '错误', '剩余', '到期', '官网', 'mibei77', '别买', '回国', '中国']

SUPPORTED_PROTOCOLS = ('vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'tuic://', 'hysteria2://')

# ====================================================

def fetch_and_decode(url):
    if not url or not url.strip():
        return []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        content = response.text.strip()
        try:
            padding = 4 - (len(content) % 4)
            if padding != 4: content += "=" * padding
            decoded_bytes = base64.b64decode(content)
            return decoded_bytes.decode('utf-8', errors='ignore').splitlines()
        except:
            return content.splitlines()
    except Exception:
        return []

def get_pure_config(link):
    if link.startswith("vmess://"):
        try:
            b64_str = link[8:].strip()
            padding = 4 - (len(b64_str) % 4)
            if padding != 4: b64_str += "=" * padding
            v_json = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
            v_json['ps'] = ""
            return f"vmess://{json.dumps(v_json, sort_keys=True)}"
        except:
            return link
    elif "#" in link:
        return link.split("#", 1)[0]
    return link

def parse_target_address(link):
    """从各种协议协议链接中，精准提取出目标服务器的 IP/域名 和 端口"""
    try:
        if link.startswith("vmess://"):
            if link.startswith("vmess://{"):
                v_json = json.loads(link[8:])
            else:
                b64_str = link[8:].strip()
                padding = 4 - (len(b64_str) % 4)
                if padding != 4: b64_str += "=" * padding
                v_json = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
            return str(v_json.get('add')), int(v_json.get('port'))
        
        elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hysteria2://']):
            # 去掉协议头
            main_part = link.split("://", 1)[1]
            # 去掉后面的参数和备注
            main_part = main_part.split("#", 1)[0].split("?", 1)[0]
            # 如果包含账号认证信息（@符号），取后面部分
            if "@" in main_part:
                main_part = main_part.rsplit("@", 1)[1]
            
            # 处理 IPv6 格式 [::1]:8080
            if main_part.startswith("["):
                endpoint, port = main_part.split("]:", 1)
                return endpoint + "]", int(port)
            else:
                if ":" in main_part:
                    endpoint, port = main_part.split(":", 1)
                    return endpoint, int(port)
    except:
        pass
    return None, None

def test_node_latency(link):
    """利用 TCP 三次握手测试节点服务器底层延迟"""
    ip, port = parse_target_address(link)
    if not ip or not port:
        return link, 99999 # 无法解析的脏数据赋予极高延迟淘汰
        
    start_time = time.perf_counter()
    try:
        # 创建网络套接字
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PING_TIMEOUT)
        # 尝试连接
        s.connect((ip, port))
        s.close()
        latency = (time.perf_counter() - start_time) * 1000 # 转换为毫秒
        return link, latency
    except Exception:
        return link, 99999

def rename_node(link, index, latency):
    try:
        custom_remark = base64.b64decode(CUSTOM_REMARK_B64).decode('utf-8')
    except Exception:
        custom_remark = "Node"
        
    # 把节点延迟（例如 145ms）直接做进节点名字里，方便在客户端选节点时一目了然
    new_name = f"{custom_remark} {index:03d} | 延迟:{int(latency)}ms"
    
    if link.startswith("vmess://"):
        try:
            if link.startswith("vmess://{"):
                v_json = json.loads(link[8:])
                v_json['ps'] = new_name
                new_b64 = base64.b64encode(json.dumps(v_json, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                return f"vmess://{new_b64}"
            
            b64_str = link[8:]
            padding = 4 - (len(b64_str) % 4)
            if padding != 4: b64_str += "=" * padding
            v_json = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            v_json['ps'] = new_name
            new_b64 = base64.b64encode(json.dumps(v_json, ensure_ascii=False).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"
        except:
            return link
    elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hysteria2://']):
        try:
            base_link = link.split("#", 1)[0]
            return f"{base_link}#{quote(new_name)}"
        except:
            return link
    return link

def main():
    print(f"=== 开始全自动测速清洗任务 {datetime.now()} ===")
    all_lines = []
    
    # 1. 下载源
    print("[*] 步骤 1/4: 正在拉取远程订阅源...")
    for url in tqdm(SOURCE_URLS, desc="下载订阅池", unit="url"):
        all_lines.extend(fetch_and_decode(url))
        
    seen_configs = set()
    unique_nodes = []
    
    # 2. 去重
    print(f"[*] 步骤 2/4: 正在进行深度非对称去重（池内共 {len(all_lines)} 行）...")
    for line in tqdm(all_lines, desc="结构去重中", unit="行"):
        line = line.strip()
        if not line.startswith(SUPPORTED_PROTOCOLS):
            continue
        if any(keyword.lower() in line.lower() for keyword in BLACKLIST_KEYWORDS):
            continue
            
        pure_config = get_pure_config(line)
        if pure_config not in seen_configs:
            seen_configs.add(pure_config)
            unique_nodes.append(line) # 保留带有原始信息的链接去测速
            
    print(f"[*] 全网初始节点：{len(all_lines)} ➔ 深度去重后独立候选：{len(unique_nodes)} 个")
    
    # 为了防止测速样本过大导致超时，我们每次最多只给前 6000 个独立节点进行测速
    test_pool = unique_nodes[:6000]
    
    # 3. 多线程高并发测速
    print(f"[*] 步骤 3/4: 正在启动 {MAX_WORKERS} 线程高并发测速筛选（测试样本数：{len(test_pool)}）...")
    alive_nodes = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交测速任务
        futures = {executor.submit(test_node_latency, node): node for node in test_pool}
        
        # 配合 tqdm 展现酷炫测速进度条
        for future in tqdm(as_completed(futures), total=len(test_pool), desc="并发测速中", unit="个"):
            node_link, latency = future.result()
            if latency < (PING_TIMEOUT * 1000): # 如果延迟在超时范围内，证明是活节点
                alive_nodes.append((node_link, latency))
                
    # 4. 按延迟从小到大排序
    alive_nodes.sort(key=lambda x: x[1])
    print(f"[*] 测速结束！存活可连通节点：{len(alive_nodes)} 个")
    
    # 截取延迟最低的前 MAX_NODES_LIMIT 名
    if len(alive_nodes) > MAX_NODES_LIMIT:
        print(f"[!] 活节点充足，已为你精选延迟最低的前 {MAX_NODES_LIMIT} 个节点作为最终产物")
        alive_nodes = alive_nodes[:MAX_NODES_LIMIT]
        
    # 5. 重命名和输出
    print(f"[*] 步骤 4/4: 正在按照延迟梯度重新分配备注命名...")
    final_nodes = []
    for i, (node, latency) in enumerate(tqdm(alive_nodes, desc="重命名排序", unit="个"), 1):
        final_nodes.append(rename_node(node, i, latency))
        
    print(f"[*] 成功重构 {len(final_nodes)} 个低延迟满血节点！")
    
    raw_text = "\n".join(final_nodes)
    sub_base64 = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')
    
    os.makedirs('output', exist_ok=True)
    with open('output/nodes.txt', 'w', encoding='utf-8') as f:
        f.write(raw_text)
    with open('output/sub.txt', 'w', encoding='utf-8') as f:
        f.write(sub_base64)
    print("[*] 完美洗牌！最优质的数据已写入 output 文件夹，等待 GitHub Actions 推送。")

if __name__ == "__main__":
    main()
