#include "coff.h"


DWORD coff(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    //COFF 目标文件没有 DOS 头，第一个字段就是 Machine，所以要先确认不是 PE。
    if (Data == NULL || Size < sizeof(IMAGE_FILE_HEADER)) {
        LOGA(ERROR_LEVEL, "文件过小, Size:%u", Size);
        return ERROR_INVALID_DATA;
    }

    if (((PWORD)Data)[0] == IMAGE_DOS_SIGNATURE) {
        LOGA(ERROR_LEVEL, "这不是COFF目标文件(它是带DOS头的PE/EXE)");
        return ERROR_INVALID_DATA;
    }

    PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)Data;

    if (FileHeader->SizeOfOptionalHeader != 0) {
        LOGA(WARNING_LEVEL, "SizeOfOptionalHeader:%#X, 目标文件一般没有可选头。", FileHeader->SizeOfOptionalHeader);
    }

    DWORD section_table_offset = sizeof(IMAGE_FILE_HEADER) + FileHeader->SizeOfOptionalHeader;
    if (section_table_offset > Size ||
        Size - section_table_offset < (DWORD)FileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) {
        LOGA(ERROR_LEVEL, "节表越界, 节数:%u, Size:%u", FileHeader->NumberOfSections, Size);
        return ERROR_INVALID_DATA;
    }

    printf("Machine:%#06X, %s.\n", FileHeader->Machine, GetMachine(FileHeader->Machine));
    printf("NumberOfSections:%d\n", FileHeader->NumberOfSections);
    printf("\n");

    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)FileHeader + section_table_offset);

    for (WORD i = 0; i < FileHeader->NumberOfSections; i++) {
        CHAR SectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        GetSectionName(&SectionHeader[i], SectionName);

        printf("Index:%d\n", i + 1);
        printf("Name:%s\n", SectionName);
        printf("\n");
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
