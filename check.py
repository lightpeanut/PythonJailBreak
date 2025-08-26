import sys
import urllib.request
import os


def main():
    """
    对一个完全未知的Python沙箱环境进行探测（鲁棒版）。
    不依赖特定的系统文件，并结合读写测试。
    所有测试结果会被收集到一个报告字符串中，并通过函数返回值返回。
    """
    report = []
    report.append("--- Robust Sandbox Evasion & Evasion Probe Report ---")

    # === 1. 通用文件读取测试 ===
    report.append("\n[1] Universal File Read Test")
    # 我们按可能性从高到低尝试读取以下目标：
    # 1. sys.executable: Python解释器本身，必须存在。
    # 2. /dev/null: 几乎所有*nix系统都存在的特殊设备文件。
    read_success = False
    targets_to_read = [sys.executable, '/dev/null']

    for target in targets_to_read:
        if not target: continue
        try:
            with open(target, 'rb') as f:  # 使用二进制模式 'rb' 避免编码错误
                f.read(16)  # 读取前16个字节
            report.append(f"✅  SUCCESS: Read from '{target}' is allowed.")
            report.append("    -> Syscalls like 'openat', 'read' are likely permitted.")
            read_success = True
            break  # 只要有一个成功，就停止尝试
        except Exception as e:
            report.append(f"INFO: Failed to read '{target}'. Reason: {type(e).__name__} - {e}")

    if not read_success:
        report.append("❌  FAILED: Could not read from any of the universal targets.")

    # === 2. 写入与回读联合测试 ===
    report.append("\n[2] Write & Read-Back Test")
    test_file_path = 'probe_io_test.tmp'
    test_content = 'sandbox_probe_content'
    try:
        # 步骤 A: 写入文件
        with open(test_file_path, 'w') as f:
            f.write(test_content)
        report.append(f"✅  Step A (Write): SUCCESS. Wrote to '{test_file_path}'.")

        # 步骤 B: 读回文件并验证内容
        try:
            with open(test_file_path, 'r') as f:
                content_read = f.read()
            if content_read == test_content:
                report.append("✅  Step B (Read-Back): SUCCESS. Verified content.")
                report.append("    -> Full file I/O (write then read) is confirmed.")
            else:
                report.append("❌  Step B (Read-Back): FAILED. Content mismatch.")
        except Exception as e:
            report.append(f"❌  Step B (Read-Back): FAILED. Could not read back file. Reason: {e}")

    except Exception as e:
        report.append(f"❌  Step A (Write): FAILED. Could not write file. Reason: {e}")
    finally:
        # 步骤 C: 清理
        if os.path.exists(test_file_path):
            try:
                os.remove(test_file_path)
                report.append("    -> Cleanup: Test file removed successfully.")
            except Exception as e:
                report.append(f"    -> WARNING: Could not remove test file. Reason: {e}")

    # === 3. 目录列举测试 (无变化) ===
    report.append("\n[3] Directory Listing Test")
    try:
        dir_contents = os.listdir('.')
        report.append(f"✅  SUCCESS: Directory listing of '.' is allowed.")
        report.append(f"    -> Contents (first 5): {str(dir_contents[:5])}")
    except Exception as e:
        report.append(f"❌  FAILED: Could not list directory contents. Reason: {e}")

    # === 4. 网络连接测试 (无变化) ===
    # 4.1 高层 HTTPS 测试
    report.append("    -> Step A: Testing high-level HTTPS request...")
    https_success = False
    try:
        # 尝试访问百度首页，超时设置为5秒
        # 添加User-Agent头，模拟浏览器，避免被一些简单的WAF拦截
        req = urllib.request.Request("https://www.baidu.com", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                report.append("    ✅  SUCCESS: Full HTTPS request to https://www.baidu.com (port 443) is allowed.")
                https_success = True
            else:
                report.append(f"    ❓  NEUTRAL: Connection allowed, but received status code {response.status}.")
    except Exception as e:
        report.append(f"    ❌  FAILED: Could not complete HTTPS request. Reason: {type(e).__name__} - {e}")

    # === 5. 环境识别 (无变化, 但依赖于文件系统权限) ===
    report.append("\n[5] Containerization Check")
    # ... (代码与上一版本相同)
    if os.path.exists('/.dockerenv'):
        report.append("✅  POSITIVE: '/.dockerenv' file found. Very likely inside a Docker container.")
    else:
        report.append("❌  NEGATIVE: '/.dockerenv' file not found.")

    try:
        with open('/proc/1/cgroup', 'r') as f:
            cgroup_content = f.read(128)
            if 'docker' in cgroup_content or 'kubepods' in cgroup_content:
                report.append(f"✅  POSITIVE: Found container keywords in '/proc/1/cgroup'.")
            else:
                report.append(f"❓  NEUTRAL: No obvious container keywords in '/proc/1/cgroup'.")
    except Exception:
        report.append("INFO: Could not read '/proc/1/cgroup' (this is expected if file reads fail).")

    # --- 最终返回 ---
    final_report_string = "\n".join(report)
    return {"result": final_report_string}