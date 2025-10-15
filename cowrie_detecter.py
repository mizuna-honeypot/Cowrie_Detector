#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import paramiko
import time
import re

def banner():
    """ツールのバナーを表示します。"""
    print("""
    ╔═══════════════════════════════════════╗
    ║          Cowrie Detector v4.2         ║
    ║        (詳細結果分析・日本語版)       ║
    ╚═══════════════════════════════════════╝
    """)

def check_ssh_banner(hostname, port):
    """ターゲットからSSHバナーを取得します。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, port))
        banner_data = sock.recv(1024).decode().strip()
        sock.close()
        return banner_data
    except Exception as e:
        print(f"[-] SSHバナーの取得に失敗しました: {e}")
        return None

def run_commands_interactive(channel, commands_to_run, indicators, confidence):
    """インタラクティブシェルを通じてコマンドを実行し、結果をスコアリングします。"""
    print("      -> インタラクティブシェル分析に切り替えます...")
    time.sleep(1)
    initial_output = channel.recv(4096).decode(errors='ignore')
    
    prompt_pattern = r'root@[\w-]+:~#'
    if re.search(prompt_pattern, initial_output):
        indicator_text = "Cowrie風のrootプロンプトパターンを検出"
        if indicator_text not in indicators:
            indicators.append(indicator_text)
            confidence += 5 # スコア: +5

    for cmd, indicator_msg in commands_to_run.items():
        try:
            channel.send(cmd + '\n')
            time.sleep(1.5)
            output = channel.recv(4096).decode(errors='ignore').strip()
            print(f"      -> コマンド '{cmd}' をシェル経由で実行しました ({len(output)} bytes)。")
            
            if cmd == 'uname -a' and '3.2.0-4-amd64' in output and indicator_msg not in indicators:
                indicators.append(indicator_msg)
                confidence += 20 # スコア: +20
            if 'phil' in output and (cmd == 'whoami' or cmd == 'cat /etc/passwd') and indicator_msg not in indicators:
                indicators.append(indicator_msg)
                confidence += 30 # スコア: +30
        except Exception as e:
            print(f"      -> インタラクティブコマンド '{cmd}' の実行中にエラー: {e}")
            break
            
    return indicators, confidence


def analyze_target(hostname, port):
    """最終的なスコアリングモデルを使用して、Cowrieの指標を分析します。"""
    indicators = []
    confidence = 0
    
    print(f"[*] 分析対象: {hostname}:{port}")
    
    ssh_banner = check_ssh_banner(hostname, port)
    if ssh_banner:
        print(f"[+] SSHバナー: {ssh_banner}")
        if "SSH-2.0-OpenSSH_6.0p1" in ssh_banner:
            indicators.append("デフォルトのCowrie SSHバナーを検出")
            confidence += 5 # スコア: +5

    print("[*] 一般的な認証情報リストを試行します...")
    
    common_credentials = [('root', 'root'), ('root', '123456'), ('admin', 'admin'), ('user', 'user'), ('phil', 'phil')]
    
    commands_to_run = {
        'whoami': "'phil'ユーザーを検出",
        'uname -a': "典型的なCowrieのカーネルバージョンを検出",
        'cat /etc/passwd': "'phil'ユーザーを検出"
    }
    
    login_success = {'root': False, 'phil': False}

    for username, password in common_credentials:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            print(f"\n    -> 試行中: {username}:{password}...")
            
            ssh.connect(hostname, port=port, username=username, password=password, timeout=10)

            print(f"[+] ログイン成功: {username}:{password}")
            if username in login_success:
                login_success[username] = True
            
            indicator_text = f"弱い認証情報を受け入れました: {username}:{password}"
            if indicator_text not in indicators:
                indicators.append(indicator_text)
                if username == 'phil':
                    confidence += 30 # 'phil'でのログイン自体が非常に強力な指標
                else:
                    confidence += 15 # スコア: +15
            
            try:
                print("    [*] 非インタラクティブなコマンド実行を試みます...")
                stdin, stdout, stderr = ssh.exec_command('whoami', timeout=5)
                stdout.read()
                print("      -> 非インタラクティブ実行は安定しています。")
            except Exception as e:
                if 'Channel closed' in str(e):
                    indicator_text = "exec_commandの失敗 (Channel closed)"
                    if indicator_text not in indicators:
                        print("      -> 即時のチャネル切断を検出しました (強力な指標)。")
                        indicators.append(indicator_text)
                        confidence += 40 # スコア: +40
                    
                    try:
                        channel = ssh.invoke_shell()
                        indicators, confidence = run_commands_interactive(channel, commands_to_run, indicators, confidence)
                        channel.close()
                    except Exception as shell_e:
                        print(f"      -> インタラクティブシェルのオープンに失敗しました: {shell_e}")
            finally:
                ssh.close()

        except paramiko.AuthenticationException:
            print(f"    [-] ログイン失敗: {username}:{password}.")
        except Exception as e:
            print(f"[-] {username}:{password} でエラーが発生しました: {e}")
    
    if login_success['phil'] and not login_success['root']:
        indicator_text = "特殊なrootログイン失敗 (モダンクライアントがブロックされました)"
        if indicator_text not in indicators:
            indicators.append(indicator_text)
            confidence += 30 # スコア: +30
        
    return indicators, confidence

def main():
    banner()
    if len(sys.argv) not in [2, 3]:
        print("使い方: python3 cowrie_detector.py <ホスト名> [ポート番号]")
        sys.exit(1)
    
    hostname = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) == 3 else 22
    indicators, confidence = analyze_target(hostname, port)
    
    print("\n" + "="*50)
    print("スキャン結果")
    print("="*50)
    
    if confidence >= 100:
        print(f"[!] 信頼スコア: {confidence} (極めて高い信頼性)")
        print("[!] 結論: デフォルト設定のCowrieハニーポットであると強く確信します。")
    elif confidence >= 70:
        print(f"[!] 信頼スコア: {confidence} (高い信頼性)")
        print("[!] 結論: 複数の強力な指標が検出されました。意図的に設定された、あるいは堅牢化されたCowrieハニーポットである可能性が高いです。")
    elif confidence >= 40:
        print(f"[!] 信頼スコア: {confidence} (中程度の信頼性)")
        print("[!] 結論: Cowrie特有の挙動がいくつか見られますが、断定するには不十分です。Cowrieハニーポットである疑いがあります。")
    elif confidence > 0:
        print(f"[?] 信頼スコア: {confidence} (低い信頼性)")
        print("[?] 結論: 弱い指標がいくつか検出されましたが、これらは他のシステムでも見られる可能性があります。Cowrieである可能性は低いですが、ゼロではありません。")
    else:
        print("[+] 信頼スコア: 0")
        print("[+] 明確なCowrieの指標は見つかりませんでした。")
        print("[+] これは本物のシステムか、非常によく設定されたハニーポットのようです。")

    if indicators:
        print("\n[+] 検出された指標:")
        unique_indicators = sorted(list(set(indicators)))
        for i, indicator in enumerate(unique_indicators, 1):
            print(f"    {i}. {indicator}")
    
    print("="*50)
    print("[*] スキャンが完了しました。")

if __name__ == "__main__":
    main()
