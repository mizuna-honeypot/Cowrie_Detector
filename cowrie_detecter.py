#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import paramiko
import threading
import time
import re

def banner():
    print("""
    ╔═══════════════════════════════════════╗
    ║           Cowrie  Detector            ║
    ║             Version 1.0               ║
    ╚═══════════════════════════════════════╝
    """)

def check_ssh_connection(hostname, port=22):
    """SSH接続をテストし、バナー情報を取得"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, port))
        
        # SSHバナーを受信
        banner_data = sock.recv(1024).decode().strip()
        sock.close()
        
        return banner_data
    except Exception as e:
        return None

def execute_command_with_retry(ssh, command, max_retries=3):
    """コマンドを複数回試行して実行"""
    for attempt in range(max_retries):
        try:
            # 新しいチャンネルを毎回作成
            transport = ssh.get_transport()
            if not transport or not transport.is_active():
                return None, f"Transport not active (attempt {attempt + 1})"
            
            channel = transport.open_session(timeout=10)
            channel.settimeout(10)
            
            # コマンド実行
            channel.exec_command(command)
            
            # 出力を読み取り
            stdout_data = b""
            stderr_data = b""
            
            # ノンブロッキングで読み取り
            while True:
                if channel.recv_ready():
                    stdout_data += channel.recv(4096)
                if channel.recv_stderr_ready():
                    stderr_data += channel.recv_stderr(4096)
                if channel.exit_status_ready():
                    break
                time.sleep(0.1)
            
            # 残りのデータを読み取り
            while channel.recv_ready():
                stdout_data += channel.recv(4096)
            while channel.recv_stderr_ready():
                stderr_data += channel.recv_stderr(4096)
            
            channel.close()
            
            return stdout_data.decode('utf-8', errors='ignore').strip(), None
            
        except Exception as e:
            if attempt == max_retries - 1:
                return None, str(e)
            time.sleep(1)  # 少し待ってから再試行
    
    return None, "Max retries exceeded"

def create_ssh_connection(hostname, port, username, password):
    """SSHコネクションを作成"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # より長いタイムアウトと詳細な設定
        ssh.connect(
            hostname, 
            port=port, 
            username=username, 
            password=password, 
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=30,
            auth_timeout=30
        )
        
        return ssh, None
    except Exception as e:
        return None, str(e)

def test_interactive_session(ssh, username):
    """インタラクティブセッションをテストして詳細な分析を行う"""
    indicators = []
    confidence_boost = 0
    
    try:
        # インタラクティブシェルを開始
        channel = ssh.invoke_shell(width=80, height=24)
        channel.settimeout(10)
        
        # プロンプトが表示されるまで待機
        time.sleep(2)
        
        # 初期出力を読み取り
        if channel.recv_ready():
            initial_output = channel.recv(4096).decode('utf-8', errors='ignore')
            print(f"[+] Initial shell output received: {len(initial_output)} bytes")
            
            # Cowrieの典型的なプロンプトパターンをチェック
            cowrie_prompts = [
                r'root@[\w-]+:~#',
                r'\w+@[\w-]+:\$',
                r'Last login:.*from.*'
            ]
            
            for pattern in cowrie_prompts:
                if re.search(pattern, initial_output):
                    indicators.append(f"Cowrie-like prompt pattern detected: {pattern}")
                    confidence_boost += 10
        
        # 複数のコマンドを順次実行
        test_commands = [
            ('whoami', 'ユーザー名確認'),
            ('pwd', 'カレントディレクトリ'),
            ('ls -la', 'ディレクトリリスト'),
            ('uname -a', 'システム情報'),
            ('cat /proc/version', 'カーネルバージョン'),
            ('ifconfig', 'ネットワーク設定'),
            ('ps aux', 'プロセスリスト'),
            ('cat /etc/passwd', 'ユーザーファイル')
        ]
        
        command_results = {}
        
        for cmd, desc in test_commands:
            try:
                # コマンド送信
                channel.send(cmd + '\n')
                time.sleep(1.5)  # コマンド実行を待機
                
                # 出力を収集
                output = ""
                start_time = time.time()
                while time.time() - start_time < 5:  # 最大5秒待機
                    if channel.recv_ready():
                        data = channel.recv(4096).decode('utf-8', errors='ignore')
                        output += data
                        if '#' in data or '$' in data:  # プロンプトが戻ってきた
                            break
                    time.sleep(0.1)
                
                command_results[cmd] = output
                print(f"[+] Command '{cmd}' executed successfully: {len(output)} bytes")
                
            except Exception as e:
                print(f"[-] Command '{cmd}' failed: {e}")
                command_results[cmd] = None
        
        channel.close()
        
        # 結果を分析
        confidence_boost += analyze_command_results(command_results, indicators)
        
    except Exception as e:
        print(f"[-] Interactive session failed: {e}")
        indicators.append("Interactive shell session failed")
        confidence_boost += 20
    
    return indicators, confidence_boost

def analyze_command_results(results, indicators):
    """コマンド結果を分析してCowrieの特徴を検出"""
    confidence_boost = 0
    
    # whoamiの結果をチェック
    if 'whoami' in results and results['whoami']:
        if 'phil' in results['whoami'].lower():
            indicators.append("Default user 'phil' detected via interactive shell")
            confidence_boost += 30
    
    # ifconfigの結果をチェック
    if 'ifconfig' in results and results['ifconfig']:
        ifconfig_output = results['ifconfig']
        # Cowrieの典型的な偽のネットワーク設定
        if '00:00:00:00:00:00' in ifconfig_output or 'HWaddr 00:00:00:00:00:00' in ifconfig_output:
            indicators.append("Invalid MAC address detected in ifconfig")
            confidence_boost += 25
        
        # Cowrieでよく見られる固定IP
        cowrie_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        for ip in cowrie_ips:
            if ip in ifconfig_output:
                indicators.append(f"Typical Cowrie IP address detected: {ip}")
                confidence_boost += 15
    
    # /etc/passwdの結果をチェック
    if 'cat /etc/passwd' in results and results['cat /etc/passwd']:
        passwd_content = results['cat /etc/passwd']
        lines = passwd_content.split('\n')
        valid_lines = [line for line in lines if ':' in line and not line.startswith('#')]
        
        if len(valid_lines) < 10:
            indicators.append(f"Suspiciously few /etc/passwd entries: {len(valid_lines)}")
            confidence_boost += 20
        
        # Cowrieのデフォルトユーザーをチェック
        if 'phil:' in passwd_content:
            indicators.append("Default Cowrie user 'phil' found in /etc/passwd")
            confidence_boost += 25
    
    # プロセスリストをチェック
    if 'ps aux' in results and results['ps aux']:
        ps_output = results['ps aux']
        # Cowrieプロセスが見えるかチェック
        cowrie_processes = ['cowrie', 'twistd', 'python.*cowrie']
        for process in cowrie_processes:
            if re.search(process, ps_output, re.IGNORECASE):
                indicators.append(f"Cowrie process detected: {process}")
                confidence_boost += 35
    
    # uname -aの結果をチェック
    if 'uname -a' in results and results['uname -a']:
        uname_output = results['uname -a']
        # Cowrieの典型的なカーネルバージョン
        cowrie_kernels = [
            '3.2.0-4-amd64',
            '2.6.26-2-686',
            'Linux debian'
        ]
        for kernel in cowrie_kernels:
            if kernel in uname_output:
                indicators.append(f"Typical Cowrie kernel version detected: {kernel}")
                confidence_boost += 15
    
    return confidence_boost

def detect_cowrie_indicators(hostname, port=22):
    """Cowrieハニーポットの検知指標をチェック"""
    indicators = []
    confidence = 0
    
    print(f"[*] Analyzing target: {hostname}:{port}")
    
    # SSH バナーチェック
    banner_info = check_ssh_connection(hostname, port)
    if banner_info:
        print(f"[+] SSH Banner: {banner_info}")
        
        # Cowrieのデフォルトバナーパターンをチェック
        cowrie_banners = [
            "SSH-2.0-OpenSSH_6.0p1",
            "SSH-2.0-OpenSSH_7.4", 
            "SSH-2.0-OpenSSH_5.1p1",
            "SSH-2.0-OpenSSH_6.6.1p1"
        ]
        
        for cb in cowrie_banners:
            if cb in banner_info:
                indicators.append(f"Default Cowrie SSH banner detected: {cb}")
                confidence += 30
                break
        
        # Debian系の古いバージョンもCowrieでよく使われる
        if "Debian" in banner_info and ("deb7u" in banner_info or "deb6u" in banner_info):
            indicators.append("Outdated Debian SSH version (typical of Cowrie)")
            confidence += 15
    else:
        print("[-] Could not retrieve SSH banner")
        return indicators, confidence
    
    # 認証テスト
    test_credentials = [
        ('root', 'root'),
        ('root', '123456'),
        ('admin', 'admin'),
        ('user', 'user'),
        ('phil', 'phil'),
        ('test', 'test'),
        ('guest', 'guest')
    ]
    
    successful_login = False
    ssh_connection = None
    login_username = None
    
    print("[*] Testing authentication...")
    
    for username, password in test_credentials:
        print(f"[*] Trying {username}:{password}")
        
        ssh, error = create_ssh_connection(hostname, port, username, password)
        if ssh:
            print(f"[+] Login successful with {username}:{password}")
            successful_login = True
            ssh_connection = ssh
            login_username = username
            
            # Cowrieは通常、弱い認証情報を受け入れる
            if password in ['root', 'admin', 'user', 'phil', 'test', '123456']:
                indicators.append(f"Weak credentials accepted: {username}:{password}")
                confidence += 25
            
            break
        else:
            print(f"[-] Login failed for {username}:{password} - {error}")
    
    if not successful_login:
        print("[-] No successful login achieved")
        return indicators, confidence
    
    # 認証成功後の詳細テスト
    print("[*] Running detailed command analysis...")
    
    # まず基本的なコマンド実行テスト
    basic_commands = ['whoami', 'pwd', 'echo test']
    working_commands = 0
    
    for cmd in basic_commands:
        result, error = execute_command_with_retry(ssh_connection, cmd)
        if result is not None:
            working_commands += 1
            print(f"[+] Basic command '{cmd}' works: {result[:50]}...")
        else:
            print(f"[-] Basic command '{cmd}' failed: {error}")
    
    if working_commands == 0:
        indicators.append("No basic commands work after authentication")
        confidence += 30
    elif working_commands < len(basic_commands):
        indicators.append("Some basic commands fail unexpectedly")
        confidence += 15
    
    # インタラクティブセッションテスト
    interactive_indicators, interactive_confidence = test_interactive_session(ssh_connection, login_username)
    indicators.extend(interactive_indicators)
    confidence += interactive_confidence
    
    # SSHコネクションを閉じる
    try:
        ssh_connection.close()
    except:
        pass
    
    return indicators, confidence

def main():
    banner()
    
    if len(sys.argv) not in [2, 3]:
        print("Usage: python cowrie_detect.py <hostname> [port]")
        print("Example: python cowrie_detect.py 192.168.1.100")
        print("Example: python cowrie_detect.py 192.168.1.100 2222")
        sys.exit(1)
    
    hostname = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) == 3 else 22
    
    print(f"[*] Starting Cowrie detection scan against {hostname}:{port}")
    print("-" * 60)
    
    try:
        indicators, confidence = detect_cowrie_indicators(hostname, port)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Scan failed with error: {e}")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    
    if indicators:
        print(f"[!] COWRIE HONEYPOT DETECTED!")
        print(f"[!] Confidence Level: {min(confidence, 100)}%")
        print("\n[+] Detected Indicators:")
        for i, indicator in enumerate(indicators, 1):
            print(f"    {i}. {indicator}")
        
        # 信頼度に基づく評価
        if confidence >= 80:
            print(f"\n[!] HIGH CONFIDENCE: This is very likely a Cowrie honeypot")
        elif confidence >= 50:
            print(f"\n[!] MEDIUM CONFIDENCE: This appears to be a Cowrie honeypot")
        else:
            print(f"\n[?] LOW CONFIDENCE: Some indicators present but inconclusive")
            
    else:
        print("[+] No clear Cowrie indicators found")
        print("[+] This appears to be a real system or a very well-configured honeypot")
    
    print("\n" + "=" * 60)
    print("[*] Scan completed")

if __name__ == "__main__":
    main()
