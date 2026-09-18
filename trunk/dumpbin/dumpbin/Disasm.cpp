#include "pch.h"
#include "Disasm.h"
#include "Public.h"
#include "log.h"


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

    // Initialize formatter. Only required when you actually plan to do instruction formatting ("disassembling"), like we do here
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Loop over the instructions in our buffer.
    // The runtime-address (instruction pointer) is chosen arbitrary here in order to better visualize relative addressing
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
Address是RVA。
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return ret;
    }

    PBYTE start = (PBYTE)ImageRvaToVa(NtHeaders, Data, Address, NULL);
    if (start == NULL) {
        LOGA(ERROR_LEVEL, "RVA 无效:%#010X", Address);
        return ERROR_INVALID_PARAMETER;
    }

    //RVA 换算成文件偏移后，偏移 + 长度必须在文件内(换算后的偏移未必等于 Address)。
    DWORD offset = (DWORD)(start - Data);
    if (offset >= Size || Length > Size - offset) {
        LOGA(ERROR_LEVEL, "长度越界, RVA:%#010X, 偏移:%u, Length:%u, Size:%u", Address, offset, Length, Size);
        return ERROR_INVALID_PARAMETER;
    }

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


//PeCallBack 只有 (Data, Size)，命令行参数通过文件级变量带进回调(命令行工具是单线程的)。
static DWORD g_disassemble_address = 0;
static DWORD g_disassemble_length = 0;


static DWORD DisassembleCallback(_In_ PBYTE Data, _In_ DWORD Size)
{
    return Disassemble(Data, Size, g_disassemble_address, g_disassemble_length);
}


DWORD Disassemble(_In_ LPCWSTR FileName, _In_ LPCWSTR AddressString, _In_ LPCWSTR LengthString)
{
    g_disassemble_address = _wtoi(AddressString);
    g_disassemble_length = _wtoi(LengthString);

    return MapFile(FileName, DisassembleCallback);
}
