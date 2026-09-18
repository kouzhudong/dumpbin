#include "pch.h"
#include "log.h"


//
// 与 LOG_LEVEL 一一对应的描述字符串，超出范围的级别用"未定义"。
//
static const wchar_t* const g_log_level_names[] = {
    L"错误信息：",
    L"警告信息：",
    L"重要信息：",
    L"普通信息：",
    L"详细信息：",
    L"跟踪信息：",
};

static const wchar_t* LogLevelName(LOG_LEVEL Level)
{
    unsigned index = static_cast<unsigned>(Level);
    if (index >= _countof(g_log_level_names)) {
        return L"未定义：";
    }

    return g_log_level_names[index];
}


CRITICAL_SECTION g_log_cs;             // 同步日志输出的对象。
ULONG g_log_level = DEFAULT_LOG_LEVEL; // 日志开关，按位表示等级。


//////////////////////////////////////////////////////////////////////////////////////////////////


static bool LevelEnabled(LOG_LEVEL Level)
{
    if (static_cast<unsigned>(Level) > MAX_LEVEL) {
        return false;
    }
    return (g_log_level & (1u << static_cast<unsigned>(Level))) != 0;
}


void LogA(IN LOG_LEVEL Level, IN char const * Format, ...)
{
    if (!LevelEnabled(Level)) {
        return;
    }

    EnterCriticalSection(&g_log_cs);

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t time[64] = {0};
    StringCchPrintfW(time, _countof(time), L"%04d-%02d-%02d %02d:%02d:%02d:%03d\t", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    printf("%ls", time);
    printf("%ls", LogLevelName(Level));

    va_list args;
    va_start(args, Format);
    vprintf(Format, args);
    va_end(args);

    LeaveCriticalSection(&g_log_cs);
}


void LogW(IN LOG_LEVEL Level, IN wchar_t const * Format, ...)
{
    if (!LevelEnabled(Level)) {
        return;
    }

    EnterCriticalSection(&g_log_cs);

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t time[64] = {0};
    StringCchPrintfW(time, _countof(time), L"%04d-%02d-%02d %02d:%02d:%02d:%03d\t", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    wprintf(L"%ls", time);
    wprintf(L"%ls", LogLevelName(Level));

    va_list args;
    va_start(args, Format);
    vwprintf(Format, args);
    va_end(args);

    LeaveCriticalSection(&g_log_cs);
}


void LogApiErrMsg(PCSTR Api)
//
// 功能：专门用于记录 Win32 API 调用失败的信息。
//
{
    DWORD LastError = GetLastError();
    LPWSTR lpvMessageBuffer = NULL;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   NULL,
                   LastError,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (LPWSTR)&lpvMessageBuffer,
                   0,
                   NULL);

    if (lpvMessageBuffer) {
        // 去掉末尾的回车换行。
        size_t x = wcslen(lpvMessageBuffer);
        if (x >= 2) {
            lpvMessageBuffer[x - 1] = 0;
            lpvMessageBuffer[x - 2] = 0;
        }

        LOGA(ERROR_LEVEL, "API:%s, LastError:%#x, Message:%ls", Api, LastError, lpvMessageBuffer);

        LocalFree(lpvMessageBuffer);
    } else {
        LOGA(ERROR_LEVEL, "API:%s, LastError:%#x", Api, LastError);
    }
}
