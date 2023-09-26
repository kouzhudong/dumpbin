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
    PULONG_PTR IATBase = (PULONG_PTR)
        ImageDirectoryEntryToDataEx(Data,
                                    FALSE,//映射（MapViewOfFile）的用FALSE，原始读取(如：ReadFile)的用TRUE。 
                                    IMAGE_DIRECTORY_ENTRY_IAT,
                                    &size, &FoundHeader);

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);

    printf("IAT Directory Information:\r\n");

    printf("IAT Directory Numbers:%zd.\r\n", DataDirectory.Size/ sizeof(ULONG));

    //这些数据的意义有待进一步的考察。

    for (DWORD i = 0; i * sizeof(ULONG) < DataDirectory.Size; i++) {
        ULONG_PTR ImportThunk = IATBase[i];

        printf("ImportThunk:%zd.\r\n", ImportThunk);

        i++;//跳过一个DWORD的0.
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD IAT(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, IAT);
}
