#include "pch.h"
#include "Resource.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


const char * GetResourceTypeString(_In_ WORD Id)
{
    const char * str = "未知";

    switch (Id) {
    case (SIZE_T)RT_CURSOR:
        str = "CURSOR";
        break;
    case (SIZE_T)RT_BITMAP:
        str = "BITMAP";
        break;
    case (SIZE_T)RT_ICON:
        str = "ICON";
        break;
    case (SIZE_T)RT_MENU:
        str = "MENU";
        break;
    case (SIZE_T)RT_DIALOG:
        str = "DIALOG";
        break;
    case (SIZE_T)RT_STRING:
        str = "STRING";
        break;
    case (SIZE_T)RT_FONTDIR:
        str = "FONTDIR";
        break;
    case (SIZE_T)RT_FONT:
        str = "FONT";
        break;
    case (SIZE_T)RT_ACCELERATOR:
        str = "ACCELERATOR";
        break;
    case (SIZE_T)RT_RCDATA:
        str = "RCDATA";
        break;
    case (SIZE_T)RT_MESSAGETABLE:
        str = "MESSAGETABLE";
        break;
    case (SIZE_T)RT_GROUP_CURSOR:
        str = "GROUP_CURSOR";
        break;
    case (SIZE_T)RT_GROUP_ICON:
        str = "GROUP_ICON";
        break;
    case (SIZE_T)RT_VERSION:
        str = "VERSION";
        break;
    case (SIZE_T)RT_DLGINCLUDE:
        str = "DLGINCLUDE";
        break;
    case (SIZE_T)RT_PLUGPLAY:
        str = "PLUGPLAY";
        break;
    case (SIZE_T)RT_VXD:
        str = "VXD";
        break;
    case (SIZE_T)RT_ANICURSOR:
        str = "ANICURSOR";
        break;
    case (SIZE_T)RT_ANIICON:
        str = "ANIICON";
        break;
    case (SIZE_T)RT_HTML:
        str = "HTML";
        break;
    case (SIZE_T)RT_MANIFEST:
        str = "MANIFEST";
        break;
    default:
        printf("Id:%#x.\r\n", Id);
        break;
    }

    return str;
}


void PrintNameString(_In_ PIMAGE_RESOURCE_DIRECTORY ResourceDirectory, _In_ PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry)
{
    if (!ResourceDirectoryEntry->NameIsString) {
        return;
    }

    auto ResourceNameString = (PIMAGE_RESOURCE_DIR_STRING_U)((PCHAR)ResourceDirectory + ResourceDirectoryEntry->NameOffset);

    // Length 是字符数(不是字节数)，缓冲区要按 WCHAR 计算，否则名字会少一半。
    SIZE_T cbName = (SIZE_T)ResourceNameString->Length * sizeof(WCHAR);

    WCHAR * buf = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbName + sizeof(WCHAR));
    if (buf == NULL) {
        LOGA(ERROR_LEVEL, "HeapAlloc 失败, Length:%u", ResourceNameString->Length);
        return;
    }

    RtlCopyMemory(buf, ResourceNameString->NameString, cbName);

    printf("NameString:%ls.\r\n", buf);

    HeapFree(GetProcessHeap(), 0, buf);
}


DWORD Resource(_In_ PBYTE Data, _In_ DWORD Size)
/*


注释：
pchunter64的资源类型超出系统定义的范围(但不是RCDATA)，
但是有NameIsString(KER)，
其实这是自定义的二进制文件（SYS)。
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_RESOURCE, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Resource.\r\n");
        return ret;
    }

    printf("Resource Descriptor Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    //////////////////////////////////////////////////////////////////////////////////////////////
    //打印第一层的PIMAGE_RESOURCE_DIRECTORY的一些信息。

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_RESOURCE_DIRECTORY ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)
        ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size, &FoundHeader);
    if (ResourceDirectory == NULL) {
        LOGA(ERROR_LEVEL, "ImageDirectoryEntryToDataEx 失败");
        return ret;
    }

    if (FoundHeader) {
        CHAR SectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        GetSectionName(FoundHeader, SectionName);
        printf("SectionName:%s.\r\n", SectionName);
    }

    printf("Characteristics:%#010X.\r\n", ResourceDirectory->Characteristics);

    CHAR TimeDateStamp[MAX_PATH] = {0};
    GetTimeDateStamp(ResourceDirectory->TimeDateStamp, TimeDateStamp);
    printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", ResourceDirectory->TimeDateStamp, ResourceDirectory->TimeDateStamp, TimeDateStamp);

    printf("Version:%d.%d.\r\n", ResourceDirectory->MajorVersion, ResourceDirectory->MinorVersion);
    printf("NumberOfNamedEntries:%#06X.\r\n", ResourceDirectory->NumberOfNamedEntries);
    printf("NumberOfIdEntries:%#06X.\r\n", ResourceDirectory->NumberOfIdEntries);
    printf("\r\n");

    //////////////////////////////////////////////////////////////////////////////////////////////
    //注意：所有层的PIMAGE_RESOURCE_DIRECTORY_ENTRY偏移都是相对于第一层的ResourceDirectory来计算的。

    WORD NumberOfEntries = ResourceDirectory->NumberOfNamedEntries + ResourceDirectory->NumberOfIdEntries;

    auto ResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((PCHAR)ResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return ret;
    }

    printf("以下是资源的详细信息：\r\n");
    printf("\r\n");

    for (int i = 0; i < NumberOfEntries; i++) {//一级处理：处理资源类型
        if (ResourceDirectoryEntry->DataIsDirectory) {//递归处理。
            auto ResourceDirectory2 = (PIMAGE_RESOURCE_DIRECTORY)((PCHAR)ResourceDirectory + ResourceDirectoryEntry->OffsetToDirectory);
            WORD NumberOfEntries2 = ResourceDirectory2->NumberOfNamedEntries + ResourceDirectory2->NumberOfIdEntries;
            auto ResourceDirectoryEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((PCHAR)ResourceDirectory2 + sizeof(IMAGE_RESOURCE_DIRECTORY));

            for (int j = 0; j < NumberOfEntries2; j++) {//二级处理：处理资源名称 
                if (ResourceDirectoryEntry2->DataIsDirectory) {//递归处理。
                    auto ResourceDirectory3 = (PIMAGE_RESOURCE_DIRECTORY)((PCHAR)ResourceDirectory + ResourceDirectoryEntry2->OffsetToDirectory);
                    WORD NumberOfEntries3 = ResourceDirectory3->NumberOfNamedEntries + ResourceDirectory3->NumberOfIdEntries;
                    auto ResourceDirectoryEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((PCHAR)ResourceDirectory3 + sizeof(IMAGE_RESOURCE_DIRECTORY));

                    for (int k = 0; k < NumberOfEntries3; k++) {//三级处理：处理资源语言
                        if (ResourceDirectoryEntry3->DataIsDirectory) {
                            printf("这是第四层，本程序只解析到这里。\r\n");
                        } else {
                            auto DataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((PCHAR)ResourceDirectory + ResourceDirectoryEntry3->OffsetToData);

                            PrintNameString(ResourceDirectory, ResourceDirectoryEntry);
                            PrintNameString(ResourceDirectory, ResourceDirectoryEntry2);
                            PrintNameString(ResourceDirectory, ResourceDirectoryEntry3);

                            // 命名类型时 Id 字段无效，不能当类型号去解释。
                            PCSTR TypeString = ResourceDirectoryEntry->NameIsString ? "命名类型" : GetResourceTypeString(ResourceDirectoryEntry->Id);

                            printf("类型：%12s, 名称：%#06X, 语言：%#06X, OffsetToData:%#010X, Size:%#010X(%d).\r\n",
                                TypeString,
                                ResourceDirectoryEntry2->Id,
                                ResourceDirectoryEntry3->Id,
                                DataEntry->OffsetToData,
                                DataEntry->Size,
                                DataEntry->Size);

                            //printf("这是个叶子。\r\n");
                        }

                        ResourceDirectoryEntry3++;
                    }
                } else {
                    printf("第二层就是叶子，不符合资源目录的一般结构。\r\n");
                }

                ResourceDirectoryEntry2++;
            }
        } else {
            printf("第一层就是叶子，不符合资源目录的一般结构。\r\n");
        }

        ResourceDirectoryEntry++;

        printf("\r\n");
    }

    //////////////////////////////////////////////////////////////////////////////////////////////

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Resource(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Resource);
}
