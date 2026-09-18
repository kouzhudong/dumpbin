#include "pch.h"
#include "TLS.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


static void PrintTlsCallbacks(_In_ PBYTE Data, _In_ DWORD Size, _In_ ULONGLONG AddressOfCallBacks, _In_ ULONGLONG ImageBase)
/*
AddressOfCallBacks 是加载后的绝对地址(VA)，要减掉 ImageBase 换成 RVA 才能在文件里定位。
回调数组以 0 结束。
*/
{
    if (AddressOfCallBacks <= ImageBase) {
        return;
    }

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        return;
    }

    PVOID CallbackTable = ImageRvaToVa(NtHeaders, Data, (ULONG)(AddressOfCallBacks - ImageBase), NULL);
    if (CallbackTable == NULL) {
        LOGA(WARNING_LEVEL, "回调数组地址无效:%#llX", AddressOfCallBacks);
        return;
    }

    DWORD count = 0;
    if (IsPE32Ex(Data, Size)) {
        PULONGLONG Callbacks = (PULONGLONG)CallbackTable;
        for (DWORD i = 0; i < 0x1000 && Callbacks[i] != 0; i++, count++) {
            printf("\tCallback[%u]:%#016llX.\r\n", i, Callbacks[i]);
        }
    } else {
        PULONG Callbacks = (PULONG)CallbackTable;
        for (DWORD i = 0; i < 0x1000 && Callbacks[i] != 0; i++, count++) {
            printf("\tCallback[%u]:%#010X.\r\n", i, Callbacks[i]);
        }
    }

    printf("回调函数的个数：%u.\r\n", count);
}


DWORD TLS(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_TLS, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有TLS.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_TLS_DIRECTORY TLSDirectory = (PIMAGE_TLS_DIRECTORY)ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_TLS, &size, &FoundHeader);
    if (TLSDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return ret;
    }

    printf("TLS Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    //TLS 目录只有一份 IMAGE_TLS_DIRECTORY，不是一个数组。

    if (IsPE32Ex(Data, Size)) {
        PIMAGE_TLS_DIRECTORY64 TLSDirectory64 = (PIMAGE_TLS_DIRECTORY64)TLSDirectory;

        printf("StartAddressOfRawData:%#016llX.\r\n", TLSDirectory64->StartAddressOfRawData);
        printf("EndAddressOfRawData:%#016llX.\r\n", TLSDirectory64->EndAddressOfRawData);
        printf("AddressOfIndex:%#016llX.\r\n", TLSDirectory64->AddressOfIndex);
        printf("AddressOfCallBacks:%#016llX.\r\n", TLSDirectory64->AddressOfCallBacks);

        printf("SizeOfZeroFill:%#010X.\r\n", TLSDirectory64->SizeOfZeroFill);

        printf("Characteristics:%#010X.\r\n", TLSDirectory64->Characteristics);

        printf("Reserved0:%#010X.\r\n", TLSDirectory64->Reserved0);
        printf("Alignment:%#010X.\r\n", TLSDirectory64->Alignment);
        printf("Reserved1:%#010X.\r\n", TLSDirectory64->Reserved1);

        PrintTlsCallbacks(Data, Size, TLSDirectory64->AddressOfCallBacks, ((PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader)->ImageBase);
    } else {
        PIMAGE_TLS_DIRECTORY32 TLSDirectory32 = (PIMAGE_TLS_DIRECTORY32)TLSDirectory;

        printf("StartAddressOfRawData:%#010X.\r\n", TLSDirectory32->StartAddressOfRawData);
        printf("EndAddressOfRawData:%#010X.\r\n", TLSDirectory32->EndAddressOfRawData);
        printf("AddressOfIndex:%#010X.\r\n", TLSDirectory32->AddressOfIndex);
        printf("AddressOfCallBacks:%#010X.\r\n", TLSDirectory32->AddressOfCallBacks);

        printf("SizeOfZeroFill:%#010X.\r\n", TLSDirectory32->SizeOfZeroFill);

        printf("Characteristics:%#010X.\r\n", TLSDirectory32->Characteristics);

        printf("Reserved0:%#010X.\r\n", TLSDirectory32->Reserved0);
        printf("Alignment:%#010X.\r\n", TLSDirectory32->Alignment);
        printf("Reserved1:%#010X.\r\n", TLSDirectory32->Reserved1);

        PrintTlsCallbacks(Data, Size, TLSDirectory32->AddressOfCallBacks, ((PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader)->ImageBase);
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD TLS(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, TLS);
}
