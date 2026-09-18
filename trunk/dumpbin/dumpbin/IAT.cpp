#include "pch.h"
#include "IAT.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD IAT(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_IAT, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有IAT.\r\n");
        return ret;
    }

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PULONG_PTR IATBase = (PULONG_PTR)ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_IAT, &size, &FoundHeader);
    if (IATBase == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    printf("IAT Directory Information:\r\n");

    //IAT 的表项是指针大小：32 位 4 字节，64 位 8 字节，必须按 sizeof(ULONG_PTR) 步进。
    DWORD count = DataDirectory.Size / sizeof(ULONG_PTR);

    printf("IAT Directory Numbers:%u.\r\n", count);

    //这些数据的意义有待进一步的考察。

    for (DWORD i = 0; i < count; i++) {
        ULONG_PTR ImportThunk = IATBase[i];

        printf("ImportThunk:%#llX.\r\n", (unsigned long long)ImportThunk);
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD IAT(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, IAT);
}
