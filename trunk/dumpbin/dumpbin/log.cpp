#include "pch.h"
#include "log.h"

#pragma warning(disable:26812)


/*
和LOG_LEVEL对应，不能少。
定义未定义是防止越界。
*/
const wchar_t* g_log_level_w[MAX_LEVEL + 1] = {
    L"错误信息：",
    L"警告信息：",
    L"重要信息：",
    L"普通信息：",
    L"冗长信息：",
    L"跟踪信息：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义："
};


CRITICAL_SECTION g_log_cs;//同步日志文件的对象。


ULONG g_log_level = DEFAULT_LOG_LEVEL;//日志开关，由配置文件控制。


//////////////////////////////////////////////////////////////////////////////////////////////////


void LogA(IN LOG_LEVEL Level, IN char const * Format, ...)
{
    if (!BitTest((const LONG*)&g_log_level, Level)) {
        return;
    }

    if (Level >= MAX_LEVEL) {
        return;
    }

    setlocale(0, "chs");//支持写汉字。

    EnterCriticalSection(&g_log_cs);

    va_list args;
    va_start(args, Format);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t time[MAX_PATH] = {0};//格式：2016-07-11 17:35:54 
    int written = wsprintfW(time, L"%04d-%02d-%02d %02d:%02d:%02d:%03d\t",
                            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    written = printf("%ls", time);

#pragma prefast(push)
#pragma prefast(disable: 33010, "warning C33010: Unchecked lower bound for enum Level used as index..")
    written = printf("%ls", g_log_level_w[Level]);
#pragma prefast(pop)       

    written = vprintf(Format, args);

    va_end(args);

    LeaveCriticalSection(&g_log_cs);
}


void LogW(IN LOG_LEVEL Level, IN wchar_t const * Format, ...)
{


}


void LogApiErrMsg(PCSTR Api)
/*
功能：专门用于记录API调用失败的信息。

做法有二：
1.返回API失败原因的详细描述，感觉用法有点别扭。
2.支持不定参数。
3.
*/
{
    LPWSTR lpvMessageBuffer;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL,
                  GetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPWSTR)&lpvMessageBuffer,//特别注意：数据后有回车换行，而且还有垃圾数据。
                  0,
                  NULL);

    //去掉回车换行
    int x = lstrlenW((LPWSTR)lpvMessageBuffer);
    lpvMessageBuffer[x - 1] = 0;
    lpvMessageBuffer[x - 2] = 0;

    LOGA(ERROR_LEVEL, "API:%s, LastError:%#x, Message:%ls", Api, GetLastError(), lpvMessageBuffer);

    LocalFree(lpvMessageBuffer);
}
