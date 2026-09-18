#include "pch.h"
#include "Globalptr.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Globalptr(_In_ PBYTE Data, _In_ DWORD Size)
/*
GLOBALPTR 里存放的是 GP 相对寻址的基址，只在 PE32 里有意义，而且没有固定的数据结构，
所以这里只把数据目录里的值打印出来，不做进一步的解析。
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_GLOBALPTR, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress && 0 == DataDirectory.Size) {
        printf("此文件没有Globalptr.\r\n");
        return ret;
    }

    printf("Globalptr Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");


    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Globalptr(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Globalptr);
}
