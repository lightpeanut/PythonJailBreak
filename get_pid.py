import ctypes
import os

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
ESRCH = 3  # No such process
EPERM = 1  # Operation not permitted


def main():
    """
    在没有 /proc 的情况下，通过暴力破解 ptrace 来扫描可附加的 PID。
    """
    report = ["--- ptrace-based PID Scanner Report ---"]
    attachable_pids = []

    try:
        libc = ctypes.CDLL(None)
    except Exception as e:
        return {"result": f"Failed to load libc: {e}"}

    # 扫描常见的进程PID范围
    for pid in range(2, 1025):
        # 尝试附加
        result = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)

        if result == 0:
            # 成功附加!
            report.append(f"🚨 FOUND attachable PID: {pid}")
            attachable_pids.append(pid)

            # **非常重要**: 立即分离，避免让目标进程一直处于暂停状态
            libc.ptrace(PTRACE_DETACH, pid, 0, 0)
        else:
            # 附加失败，检查原因
            errno = ctypes.get_errno()
            if errno == EPERM:
                # 进程存在，但我们权限不够
                # 这也是一种信息泄露，我们知道了这个PID是存活的
                pass  # 可以选择不报告，以保持输出简洁
            elif errno == ESRCH:
                # 进程不存在，这是最常见的情况
                pass

    if attachable_pids:
        report.append(f"\n✅ Summary: Found {len(attachable_pids)} attachable PID(s): {attachable_pids}")
        report.append("    -> You can now use one of these PIDs in the memory read/write script.")
    else:
        report.append("\n❌ Summary: No attachable PIDs found in the scanned range (2-1024).")

    return {"result": "\n".join(report)}