import socket
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_proxy(ip, port):
    try:
        # 尝试连接到指定IP和端口
        with socket.create_connection((ip, port), timeout=1) as sock:
            # 发送HTTP请求头
            sock.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
            # 接收响应
            response = sock.recv(1024).decode()
            # 检查响应是否包含HTTP标识
            if "HTTP/" in response:
                # 格式化代理地址
                proxy = f"http://{ip}:{port}"
                # 验证代理是否可用
                if test_proxy(proxy):
                    return proxy
    except (socket.timeout, ConnectionRefusedError, OSError):
        # 处理连接异常
        return None

def test_proxy(proxy):
    try:
        # 创建HTTP客户端，设置代理
        with httpx.Client(proxies={'http://': proxy, 'https://': proxy}, timeout=2) as client:
            # 发送请求到Google
            response = client.get('http://www.google.com')
            # 检查响应状态码
            if response.status_code == 200:
                return True
    except httpx.RequestError:
        # 处理请求异常
        return False
    return False

def ip_range(start, end):
    start = list(map(int, start.split('.')))
    end = list(map(int, end.split('.')))
    temp = start
    ip_range_list = []

    ip_range_list.append(start[:])
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1, 0):
            if start[i] == 256:
                start[i] = 0
                start[i-1] += 1
        temp = start[:]
        ip_range_list.append(temp)
    return ['.'.join(map(str, ip)) for ip in ip_range_list]

def scan_ip_range(ip_segments, ports, max_workers=100):
    open_proxies = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for segment in ip_segments:
            ips = ip_range(segment['start'], segment['end'])
            for ip in ips:
                for port in ports:
                    futures.append(executor.submit(check_proxy, ip, port))
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_proxies.append(result)
                print(f"Found open proxy: {result}")

    return open_proxies

if __name__ == "__main__":
    # IP segments for scanning
    ip_segments = [
        {'start': '136.0.0.1', 'end': '136.255.255.255'},
        {'start': '50.0.0.1', 'end': '50.255.255.255'},
        {'start': '1.0.0.1', 'end': '1.255.255.255'},
        {'start': '154.0.0.1', 'end': '154.255.255.255'},
        {'start': '150.0.0.1', 'end': '150.255.255.255'}
    ]
    
    # Common proxy ports
    ports = [8080, 3128, 8888, 80, 8000, 1080]

    open_proxies = scan_ip_range(ip_segments, ports, max_workers=500)
    print(f"Total open proxies found: {len(open_proxies)}")
    
