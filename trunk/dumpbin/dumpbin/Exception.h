#pragma once

#include "pch.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////
//一下代码摘自：
//https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=vs-2019
//https://docs.microsoft.com/es-mx/cpp/build/exception-handling-x64?view=vs-2017


typedef unsigned char UBYTE;//自己定义。


typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SPARE_CODE1,     //摘自：\WRK-v1.2\public\sdk\inc\ntamd64.h
    UWOP_SPARE_CODE2,     //摘自：\WRK-v1.2\public\sdk\inc\ntamd64.h
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;


#ifndef _WIN64
#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04
#endif

typedef struct _UNWIND_INFO {//SDK里没有定义，WDK有定义。
    UBYTE Version : 3;
    UBYTE Flags : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;


#ifndef _WIN64
typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;
#endif


#define GetUnwindCodeEntry(info, index) \
    ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) \
    ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) \
    ((PEXCEPTION_HANDLER)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) \
    ((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) \
    ((PVOID)((PULONG)GetLanguageSpecificData(info) + 1)


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Exception(_In_ LPCWSTR FileName);
