#include "pch.h"
#include "Disasm.h"
#include "Public.h"
#include "log.h"

#include <Zydis/Zydis.h>
//#include ".\lib\zydis\include\Zydis\Zydis.h"

#pragma comment(lib, "Zydis.lib") 


//////////////////////////////////////////////////////////////////////////////////////////////////


void Disasm64(_In_ ZyanU64 runtime_address, _In_ PBYTE data, _In_ const SIZE_T length)
{
    // Initialize decoder context
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    // Initialize formatter. Only required when you actually plan to do instruction
    // formatting ("disassembling"), like we do here
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Loop over the instructions in our buffer.
    // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
    // visualize relative addressing
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, length - offset, &instruction))) {
        printf("%016" PRIX64 "  ", runtime_address);// Print current instruction pointer.

        // Format & print the binary instruction structure to human readable format
        char buffer[MAX_PATH] = {0};
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);
        puts(buffer);

        offset += instruction.length;
        runtime_address += instruction.length;
    }
}


void Disasm32(_In_ DWORD runtime_address, _In_ PBYTE data, _In_ const SIZE_T length)
{
    // Initialize decoder context
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
    //ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);

    // Initialize formatter. Only required when you actually plan to do instruction
    // formatting ("disassembling"), like we do here
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Loop over the instructions in our buffer.
    // The runtime-address (instruction pointer) is chosen arbitrary here in order to better
    // visualize relative addressing
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, length - offset, &instruction))) {
        printf("%#010X" "  ", runtime_address);// Print current instruction pointer.

        // Format & print the binary instruction structure to human readable format
        char buffer[MAX_PATH] = {0};
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);
        puts(buffer);

        offset += instruction.length;
        runtime_address += instruction.length;
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Disassemble(_In_ PBYTE Data, _In_ DWORD Size, _In_ DWORD Address, _In_ DWORD Length)
/*
Address应该叫Offset.
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    if (Address > Size) {
        return ret;
    }

    if (Length > Size) {
        return ret;
    }

    //反正是在异常处理里的，都不检查了。

    //PBYTE start = Data + Address;

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);
    PBYTE start = (PBYTE)ImageRvaToVa(NtHeaders, Data, Address, NULL);

    if (IsPE32Ex(Data, Size)) {
        PIMAGE_NT_HEADERS64 NtHeaders64 = (PIMAGE_NT_HEADERS64)NtHeaders;
        ZyanU64 runtime_address = (ZyanU64)Address + NtHeaders64->OptionalHeader.ImageBase;//仿照IDA的显示。
        //ZyanU64 runtime_address = (ZyanU64)Address + Data;//本程序的真实地址。

        Disasm64(runtime_address, start, (const SIZE_T)Length);
    } else {
        PIMAGE_NT_HEADERS32 NtHeaders32 = (PIMAGE_NT_HEADERS32)NtHeaders;
        DWORD runtime_address = (DWORD)Address + NtHeaders32->OptionalHeader.ImageBase;//仿照IDA的显示。
        //DWORD runtime_address = (DWORD)Address + Data;//本程序的真实地址。

        Disasm32(runtime_address, start, (const SIZE_T)Length);
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Disassemble(_In_ LPCWSTR FileName, _In_ LPCWSTR AddressString, _In_ LPCWSTR LengthString)
{
    DWORD Address = _wtoi(AddressString);
    DWORD Length = _wtoi(LengthString);

    //////////////////////////////////////////////////////////////////////////////////////////////

    DWORD LastError = ERROR_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapFile = NULL;
    PBYTE FileContent = NULL;

    if (IsWow64()) {//在wow64下关闭文件重定向。
        BOOLEAN bRet = Wow64EnableWow64FsRedirection(FALSE);
        _ASSERTE(bRet);
    }

    __try {
        hFile = CreateFile(FileName,
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFile");
            __leave;
        }

        LARGE_INTEGER FileSize = {0};
        if (0 == GetFileSizeEx(hFile, &FileSize)) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("GetFileSizeEx");
            __leave;
        }

        if (0 == FileSize.QuadPart) {//如果文件大小为0.
            LastError = ERROR_EMPTY;
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        if (FileSize.HighPart) {//暂时不支持大于4G的文件。
            LastError = ERROR_EMPTY;
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            __leave;
        }

        hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* 空文件则返回失败 */
        if (hMapFile == NULL) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        FileContent = (PBYTE)MapViewOfFile(hMapFile, SECTION_MAP_READ, NULL, NULL, 0/*映射所有*/);
        if (FileContent == NULL) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        __try {
            LastError = Disassemble(FileContent, FileSize.LowPart, Address, Length);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LastError = GetExceptionCode();
            LOGA(ERROR_LEVEL, "ExceptionCode:%#x", LastError);
        }
    } __finally {
        if (FileContent) {
            UnmapViewOfFile(FileContent);
        }

        if (hMapFile) {
            CloseHandle(hMapFile);
        }

        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }
    }

    if (IsWow64()) {
        BOOLEAN bRet = Wow64EnableWow64FsRedirection(TRUE);//Enable WOW64 file system redirection. 
        _ASSERTE(bRet);
    }

    return LastError;
}
