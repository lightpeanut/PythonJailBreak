import ctypes
import os


def main():
    """
    通过 ctypes 直接调用高危系统调用，探测 seccomp 黑名单的遗漏。
    """
    report = []
    report.append("--- High-Risk Syscall Probe Report ---")

    # 获取 libc 和 syscall 函数
    try:
        libc = ctypes.CDLL(None)
        syscall = libc.syscall
    except Exception as e:
        return {"result": f"❌ FAILED: Could not load libc or find syscall function. Reason: {e}"}

    # x86_64架构下需要探测的高危系统调用列表 (名称, 编号)
    syscalls_to_probe = [
        ("ptrace", 101),
        ("bpf", 321),
        ("userfaultfd", 323),
        ("unshare", 272),
        ("setns", 308),
        ("mount", 165),
    ]

    for name, number in syscalls_to_probe:
        report.append(f"\n[+] Probing syscall: {name} ({number})")

        # 我们用无效的参数（0）去调用，只关心返回值和错误码
        # 这足以判断 syscall 是否被 seccomp 策略所允许
        result = syscall(number, 0, 0, 0, 0, 0, 0)

        # 获取调用后的错误码
        errno = ctypes.get_errno()

        if result == 0:
            # 返回0通常意味着成功，或者至少syscall被内核处理了
            report.append(
                f"    🚨🚨🚨 SUCCESS (returns 0): Syscall '{name}' seems to be ALLOWED. This is a potential breakthrough!")
        elif result == -1:
            # 返回-1表示失败，我们需要检查错误码 errno
            error_str = os.strerror(errno)
            if errno == 1:  # EPERM (Operation not permitted)
                report.append(
                    f"    ✅ BLOCKED (EPERM): Syscall '{name}' is blocked by a security policy (likely seccomp).")
            elif errno == 22:  # EINVAL (Invalid argument)
                report.append(
                    f"    ⚠️ POTENTIALLY ALLOWED (EINVAL): Syscall '{name}' was processed by the kernel but rejected the arguments. The syscall itself is NOT blocked by seccomp!")
            elif errno == 38:  # ENOSYS (Function not implemented)
                report.append(
                    f"    ✅ BLOCKED (ENOSYS): Syscall '{name}' is disabled in the kernel or blocked by seccomp.")
            else:
                report.append(f"    ❓ UNKNOWN (returns -1, errno={errno}): {error_str}")
        else:
            report.append(f"    ❓ UNKNOWN (returns {result}): The syscall returned an unexpected value.")

    final_report_string = "\n".join(report)
    return {"result": final_report_string}