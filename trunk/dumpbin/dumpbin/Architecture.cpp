#include "pch.h"
#include "Architecture.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Architecture(_In_ PBYTE Data, _In_ DWORD Size)
/*
有待测试。

参考：\win2k\trunk\private\ntos\dll\ldrsnap.c的AlphaFindArchitectureFixups。

PIMAGE_ARCHITECTURE_ENTRY
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Architecture.\r\n");
        return ret;
    }

    DebugBreak();

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL; 
    PIMAGE_ARCHITECTURE_HEADER BoundImportDirectory = (PIMAGE_ARCHITECTURE_HEADER)
        ImageDirectoryEntryToDataEx(Data,
                                    FALSE,//映射（MapViewOfFile）的用FALSE，原始读取(如：ReadFile)的用TRUE。 
                                    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
                                    &size, &FoundHeader);

    printf("Architecture Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    //有几个IMAGE_ARCHITECTURE_HEADER结构呢？



    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Architecture(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Architecture);
}
