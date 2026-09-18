#include "pch.h"
#include "Exception.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void GetUnwFlag(_In_ BYTE Flags, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
/*
Flags 是 5 位，EHANDLER/UHANDLER/CHAININFO 可能同时出现(如 1|4)，所以要按位拼接。
*/
{
    String[0] = '\0';

    if (0 == Flags) {
        StringCchCopyA(String, cchDest, "None");//微软的dumpbin显示的是这个。
        return;
    }

    if (Flags & UNW_FLAG_EHANDLER) {
        StringCchCatA(String, cchDest, "EHANDLER ");
    }

    if (Flags & UNW_FLAG_UHANDLER) {
        StringCchCatA(String, cchDest, "UHANDLER ");
    }

    if (Flags & UNW_FLAG_CHAININFO) {
        StringCchCatA(String, cchDest, "CHAININFO ");
    }
}


PCSTR GetUnwOpCodes(_In_ BYTE UnwindOp)
{
    PCSTR UnwOpCodes = NULL;

    switch (UnwindOp) {
    case UWOP_PUSH_NONVOL:
        UnwOpCodes = "PUSH_NONVOL";
        break;
    case UWOP_ALLOC_LARGE:
        UnwOpCodes = "ALLOC_LARGE";
        break;
    case UWOP_ALLOC_SMALL:
        UnwOpCodes = "ALLOC_SMALL";
        break;
    case UWOP_SET_FPREG:
        UnwOpCodes = "SET_FPREG";
        break;
    case UWOP_SAVE_NONVOL:
        UnwOpCodes = "SAVE_NONVOL";
        break;
    case UWOP_SAVE_NONVOL_FAR:
        UnwOpCodes = "SAVE_NONVOL_FAR";
        break;
    case UWOP_SPARE_CODE1:
        UnwOpCodes = "EPILOG";//微软的dumpbin显示的是这个。
        break;
    case UWOP_SPARE_CODE2:
        UnwOpCodes = "SPARE_CODE2";
        break;
    case UWOP_SAVE_XMM128:
        UnwOpCodes = "SAVE_XMM128";
        break;
    case UWOP_SAVE_XMM128_FAR:
        UnwOpCodes = "SAVE_XMM128_FAR";
        break;
    case UWOP_PUSH_MACHFRAME:
        UnwOpCodes = "PUSH_MACHFRAME";
        break;
    default:
        UnwOpCodes = "未知";
        break;
    }

    return UnwOpCodes;
}


const char * GetRegister(unsigned char FrameRegister)
/*
https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160&viewFallbackFrom=vs-2017
*/
{
    const char * c = "";

    switch (FrameRegister) {
    case 0:
        c = "RAX";
        break;
    case 1:
        c = "RCX";
        break;
    case 2:
        c = "RDX";
        break;
    case 3:
        c = "RBX";
        break;
    case 4:
        c = "RSP";
        break;
    case 5:
        c = "RBP";
        break;
    case 6:
        c = "RSI";
        break;
    case 7:
        c = "RDI";
        break;
    case 8:
        c = "R8";
        break;
    case 9:
        c = "R9";
        break;
    case 10:
        c = "R10";
        break;
    case 11:
        c = "R11";
        break;
    case 12:
        c = "R12";
        break;
    case 13:
        c = "R13";
        break;
    case 14:
        c = "R14";
        break;
    case 15:
        c = "R15";
        break;
    default:
        break;
    }

    return c;
}


DWORD Exception(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Exception.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    //PRUNTIME_FUNCTION
    PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)
        ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &size, &FoundHeader);
    if (ExceptionDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return ret;
    }

    printf("Exception Directory Information:\r\n");

    // 数据目录里的 Size 未必和实际长度一致，取小的那个作为遍历上界。
    DWORD total = (size != 0 && size < DataDirectory.Size) ? size : DataDirectory.Size;

    printf("Exception Function Numbers:%zu.\r\n", total / sizeof(_IMAGE_RUNTIME_FUNCTION_ENTRY));

    printf("\r\n");

    for (DWORD i = 0; i * sizeof(_IMAGE_RUNTIME_FUNCTION_ENTRY) < total; i++, ExceptionDirectory++) {
        printf("index:%06u.\r\n", i);

        printf("BeginAddress:%#010X.\r\n", ExceptionDirectory->BeginAddress);
        printf("EndAddress:%#010X.\r\n", ExceptionDirectory->EndAddress);
        printf("UnwindInfoAddress:%#010X.\r\n", ExceptionDirectory->UnwindInfoAddress);

        PUNWIND_INFO UnwindInfoAddress = (PUNWIND_INFO)ImageRvaToVa(NtHeaders, Data, ExceptionDirectory->UnwindInfoAddress, NULL);
        if (UnwindInfoAddress == NULL) {
            // 调试版 PE 是增量链接的，.pdata 里存在全 0 的表项(UnwindInfoAddress 也为 0)，此时转换不出地址。
            printf("\tUnwindInfo 无效(RVA:%#010X).\r\n", ExceptionDirectory->UnwindInfoAddress);
            printf("\r\n");
            continue;
        }

        CHAR Flags[MAX_PATH] = {0};
        GetUnwFlag(UnwindInfoAddress->Flags, Flags, _countof(Flags));

        printf("\tVersion:%d.\r\n", UnwindInfoAddress->Version);
        printf("\tFlags:%d, %s.\r\n", UnwindInfoAddress->Flags, Flags);
        printf("\tSizeOfProlog:%d.\r\n", UnwindInfoAddress->SizeOfProlog);
        printf("\tCountOfCodes:%d.\r\n", UnwindInfoAddress->CountOfCodes);
        // FrameRegister 为 0 表示没有帧寄存器，此时不该按 RAX 去解释。
        printf("\tFrameRegister:%d, %s.\r\n", UnwindInfoAddress->FrameRegister,
               UnwindInfoAddress->FrameRegister ? GetRegister(UnwindInfoAddress->FrameRegister) : "None");
        printf("\tFrameOffset:%d.\r\n", UnwindInfoAddress->FrameOffset);

        PUNWIND_CODE temp = UnwindInfoAddress->UnwindCode;

        for (BYTE j = 0; j < UnwindInfoAddress->CountOfCodes; j++) {
            printf("\t\tindex:%d, CodeOffset:%d, UnwindOp:%d(%s), OpInfo:%d, FrameOffset:%d.\r\n",
                j + 1,
                temp->CodeOffset,
                temp->UnwindOp,
                GetUnwOpCodes(temp->UnwindOp),
                temp->OpInfo,
                temp->FrameOffset);

            temp++;
        }

        printf("\r\n");
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Exception(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Exception);
}
