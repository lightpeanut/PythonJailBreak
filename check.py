import os
import socket


def main():
    """
    对一个受限的Python沙箱环境进行探测。
    所有测试结果会被收集到一个报告字符串中，并通过函数返回值返回。
    """
    report = []
    report.append("--- Sandbax Escape & Evasion Probe Report ---")

    # === 1. 文件读取测试 ===
    report.append("\n[1] File Read Test")
    try:
        # /proc/self/status 是一个无害且一定存在的文件，适合用于探测
        with open('/proc/self/status', 'r') as f:
            f.read(128)  # 只读一小部分，避免返回内容过长
        report.append("✅  SUCCESS: Read from '/proc/self/status' is allowed.")
        report.append("    -> Syscalls like 'openat', 'read', 'close' are likely permitted.")
    except Exception as e:
        report.append(f"❌  FAILED: Could not read file. Reason: {e}")

    # === 2. 文件写入测试 ===
    report.append("\n[2] File Write Test")
    test_file_path = 'probe_test.tmp'
    try:
        with open(test_file_path, 'w') as f:
            f.write('probe')
        report.append(f"✅  SUCCESS: Write to current directory ('{test_file_path}') is allowed.")
        report.append("    -> Syscall 'write' is likely permitted.")
        # 清理测试文件
        try:
            os.remove(test_file_path)
            report.append("    -> Cleanup: Test file removed successfully.")
        except Exception as e:
            report.append(f"    -> WARNING: Could not remove test file. Reason: {e}")
    except Exception as e:
        report.append(f"❌  FAILED: Could not write file. Reason: {e}")

    # === 3. 目录列举测试 ===
    report.append("\n[3] Directory Listing Test")
    try:
        # 列出当前目录的内容
        dir_contents = os.listdir('.')
        report.append(f"✅  SUCCESS: Directory listing is allowed.")
        # 只显示前5个条目，防止结果过长
        report.append(f"    -> Contents (first 5): {dir_contents[:5]}")
    except Exception as e:
        report.append(f"❌  FAILED: Could not list directory contents. Reason: {e}")

    # === 4. 网络连接测试 (Egress) ===
    report.append("\n[4] Network Egress Test")
    try:
        # 尝试连接 Google 的 DNS 服务器，这是一个常见的外联测试目标
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)  # 设置3秒超时
        s.connect(('8.8.8.8', 53))
        s.close()
        report.append("✅  SUCCESS: Outbound network connection to 8.8.8.8:53 is allowed.")
        report.append("    -> Syscalls 'socket', 'connect' are likely permitted.")
    except Exception as e:
        # 异常类型可以提供很多信息，例如 PermissionError vs Timeout
        report.append(f"❌  FAILED: Could not establish network connection. Reason: {type(e).__name__} - {e}")

    # === 5. 环境识别 (是否在容器内) ===
    report.append("\n[5] Containerization Check")
    if os.path.exists('/.dockerenv'):
        report.append("✅  POSITIVE: '/.dockerenv' file found. Very likely inside a Docker container.")
    else:
        report.append("❌  NEGATIVE: '/.dockerenv' file not found.")

    try:
        with open('/proc/1/cgroup', 'r') as f:
            cgroup_content = f.read(128)  # 读取一小部分
            if 'docker' in cgroup_content or 'kubepods' in cgroup_content:
                report.append(f"✅  POSITIVE: Found container keywords in '/proc/1/cgroup'.")
            else:
                report.append(f"❓  NEUTRAL: No obvious container keywords in '/proc/1/cgroup'.")
    except Exception:
        report.append("❌  FAILED: Could not read '/proc/1/cgroup'.")

    # --- 最终返回 ---
    final_report_string = "\n".join(report)
    return {"result": final_report_string}
