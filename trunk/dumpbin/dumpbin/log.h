#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//
// 日志级别。按位定义，最大有效个数 = ULONG 的位数。
// 注意：位是从 0 开始的，最低位的含义也是最重的。
//
typedef enum _LOG_LEVEL {
    ERROR_LEVEL = 0,
    WARNING_LEVEL = 1,
    IMPORTANT_INFO_LEVEL,
    NORMAL_INFO_LEVEL,
    VERBOSE_INFO_LEVEL,
    TRACE_LEVEL,

    MAX_LEVEL = 31
} LOG_LEVEL;


#define DEFAULT_LOG_LEVEL ((1u << ERROR_LEVEL) | (1u << WARNING_LEVEL) | (1u << IMPORTANT_INFO_LEVEL))


//////////////////////////////////////////////////////////////////////////////////////////////////


extern CRITICAL_SECTION g_log_cs;
extern ULONG g_log_level;


void LogA(IN LOG_LEVEL Level, IN char const * Format, ...);
void LogW(IN LOG_LEVEL Level, IN wchar_t const * Format, ...);
void LogApiErrMsg(PCSTR Api);


#define __FILENAME__  (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(_CRT_WIDE(__FILE__), L'\\') ? wcsrchr(_CRT_WIDE(__FILE__), L'\\') + 1 : _CRT_WIDE(__FILE__))


// LOGW: 输出宽字符日志。Format 必须是字符串字面量。
#define LOGW(Level, Format, ...) \
    do { LogW((Level), L"FILE:%ls, LINE:%d, " Format, __FILENAMEW__, __LINE__, ##__VA_ARGS__); } while (0)

// LOGA: 输出多字节日志。Format 必须是字符串字面量。
#define LOGA(Level, Format, ...) \
    do { LogA((Level), "FILE:%s, LINE:%d, " Format, __FILENAME__, __LINE__, ##__VA_ARGS__); } while (0)
