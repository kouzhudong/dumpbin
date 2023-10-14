#include "coff.h"


DWORD coff(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;
    PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)Data;
    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)FileHeader + sizeof(IMAGE_FILE_HEADER));

    printf("NumberOfSections:%d\n", FileHeader->NumberOfSections);
    printf("\n");

    for (WORD i = 0; i < FileHeader->NumberOfSections; i++) {
        printf("Index:%d\n", i + 1);
        printf("Name:%s\n", SectionHeader->Name);
        printf("\n");

        SectionHeader++;
    }





    return ret;
}


DWORD coff(_In_ LPCWSTR FileName)
/*
专门处理obj的，不处理lib.
*/
{
    return MapFile(FileName, coff);
}
