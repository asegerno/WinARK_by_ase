/* mingw_compat_stub.c
 * MinGW(fbc64) static-link compatibility stub.
 * Provides MSVC Debug-artifact instrumentation symbols (prebuilt udis86.lib).
 * Normal MSVC build (into SnowSwordCore.lib): __stdio_common_vsprintf impl is
 * excluded (ucrt.lib already exports it); other symbols are unreferenced so the
 * MSVC test link never pulls this object in.
 * MinGW/GNU-ld direct link: compile a special object with /DSS_MINGW_STUB
 * (cl /DSS_MINGW_STUB) to get the __stdio_common_vsprintf implementation, which
 * forwards to _vsnprintf (plain declaration here, resolved from msvcrt by ld).
 */
#include "pch.h"
#include <stddef.h>
#include <stdarg.h>

void __CheckForDebuggerJustMyCode(void) { }

void __GSHandlerCheck(void) { }

void __security_check_cookie(size_t cookie) { (void)cookie; }

void _RTC_CheckStackVars(void *esf, void *pdesc) { (void)esf; (void)pdesc; }

void _RTC_InitBase(void) { }

void _RTC_Shutdown(void) { }

/* UCRT internal printf family: MSVC compiles _vsnprintf/_snprintf/_snprintf_s
 * into __stdio_common_vsprintf (LEGACY_VSPRINTF option).
 * - MSVC link side: excluded (see header comment).
 * - MinGW(fbc64)/GNU-ld side: msvcrt has no __stdio_common_vsprintf, so provide
 *   a real implementation forwarding to msvcrt's _vsnprintf. */
#if !defined(_MSC_VER) || defined(SS_MINGW_STUB)

int __cdecl _vsnprintf(char *buffer, size_t bufferCount, const char *format, va_list argList);

int __cdecl __stdio_common_vsprintf(
    unsigned __int64 options, char *buffer, size_t bufferCount,
    const char *format, void *locale, va_list argList)
{
    (void)options;
    (void)locale;
    if (bufferCount == 0) {
        return -1;
    }
    int n = _vsnprintf(buffer, bufferCount, format, argList);
    if (n < 0) {
        buffer[bufferCount - 1] = '\0';
        return -1;
    }
    if ((size_t)n >= bufferCount) {
        buffer[bufferCount - 1] = '\0';
        return -1;
    }
    return n;
}

/* MSVC 对 UCRT 导入函数的引用是 __imp_ 前缀的数据符号（函数指针）。
 * GNU-ld 需要该数据符号存在才能解析 MSVC obj 的重定位。
 * 注意：MSVC 编译器把裸的 __imp_ 前缀标识符当作 dllimport 声明（吞掉定义），
 * 必须用 __declspec(dllexport) 强制生成数据定义；.drectve 的 /EXPORT 项
 * 对 GNU-ld 仅为无害 warning。 */
/* The MSVC build uses core_link/imp_stub.s as the sole data-symbol owner. */
#if !defined(_MSC_VER)
__declspec(dllexport) int (__cdecl *__imp___stdio_common_vsprintf)(
    unsigned __int64 options, char *buffer, size_t bufferCount,
    const char *format, void *locale, va_list argList) = __stdio_common_vsprintf;
#endif

#endif /* !_MSC_VER || SS_MINGW_STUB */
