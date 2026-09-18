#include "pch.h"
#include "Export.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Export(_In_ PBYTE Data, _In_ DWORD Size)
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_EXPORT, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有EXPORT.\r\n");
        return ret;
    }

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    if (NtHeaders == NULL) {
        LOGA(ERROR_LEVEL, "ImageNtHeader 失败");
        return ret;
    }

    /*
    导出目录可以用三种等价的方式取到：
    1. ImageRvaToVa(NtHeaders, Data, DataDirectory.VirtualAddress, NULL)
    2. ImageDirectoryEntryToDataEx(Data, FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size, &FoundHeader)
    3. 先 Rva2Va 算出文件偏移，再加到 Data 上（这种做法在转换失败时会得到 Data 本身，不安全）
    这里统一用第一种。
    */
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(NtHeaders, Data, DataDirectory.VirtualAddress, NULL);
    if (ExportDirectory == NULL) {
        LOGA(ERROR_LEVEL, "导出目录地址无效:%#010X", DataDirectory.VirtualAddress);
        return ret;
    }

    //获取这个数据在哪个SECTION里。
    PIMAGE_SECTION_HEADER SectionHeader = ImageRvaToSection(NtHeaders, Data, DataDirectory.VirtualAddress);
    if (SectionHeader) {
        CHAR SectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        GetSectionName(SectionHeader, SectionName);
        printf("SectionName:%s.\r\n", SectionName);
    }

    printf("Export Directory Information:\r\n");

    printf("Characteristics:%#010X.\r\n", ExportDirectory->Characteristics);//保留，必须为 0。
    CHAR TimeDateStamp[MAX_PATH] = {0};
    GetTimeDateStamp(ExportDirectory->TimeDateStamp, TimeDateStamp);
    printf("TimeDateStamp:%d(%#010X), 时间戳：%s.\r\n", ExportDirectory->TimeDateStamp, ExportDirectory->TimeDateStamp, TimeDateStamp);
    printf("Version:%d.%d.\r\n", ExportDirectory->MajorVersion, ExportDirectory->MinorVersion);
    printf("Name:%#010X.\r\n", ExportDirectory->Name);
    printf("Base:%#010X.\r\n", ExportDirectory->Base);
    printf("NumberOfFunctions:%d(%#010X).\r\n", ExportDirectory->NumberOfFunctions, ExportDirectory->NumberOfFunctions);
    printf("NumberOfNames:%d(%#010X).\r\n", ExportDirectory->NumberOfNames, ExportDirectory->NumberOfNames);
    printf("AddressOfFunctions:%#010X.\r\n", ExportDirectory->AddressOfFunctions);
    printf("AddressOfNames:%#010X.\r\n", ExportDirectory->AddressOfNames);
    printf("AddressOfNameOrdinals:%#010X.\r\n", ExportDirectory->AddressOfNameOrdinals);

    PCHAR DllName = (PCHAR)ImageRvaToVa(NtHeaders, Data, (ULONG)ExportDirectory->Name, NULL);
    printf("Name:%s.\r\n", DllName != NULL ? DllName : "(无效)");

    printf("只有序数没有名字的函数的个数:%d.\r\n", ExportDirectory->NumberOfFunctions - ExportDirectory->NumberOfNames);

    PULONG FunctionsTableBase = (PULONG)ImageRvaToVa(NtHeaders, Data, (ULONG)ExportDirectory->AddressOfFunctions, NULL);
    PULONG NameTableBase = (PULONG)ImageRvaToVa(NtHeaders, Data, (ULONG)ExportDirectory->AddressOfNames, NULL);
    PUSHORT OrdinalTableBase = (PUSHORT)ImageRvaToVa(NtHeaders, Data, (ULONG)ExportDirectory->AddressOfNameOrdinals, NULL);
    if (FunctionsTableBase == NULL || NameTableBase == NULL || OrdinalTableBase == NULL) {
        LOGA(ERROR_LEVEL, "导出表地址无效");
        return ret;
    }

    //只打印有名字的函数。
    for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++) {
        // 序号表里存的是函数表下标，必须落在函数表范围内。
        if (OrdinalTableBase[i] >= ExportDirectory->NumberOfFunctions) {
            LOGA(WARNING_LEVEL, "序号表越界, index:%u, 序号:%u", i, OrdinalTableBase[i]);
            continue;
        }

        PCHAR ApiName = (PCHAR)ImageRvaToVa(NtHeaders, Data, (ULONG)NameTableBase[i], NULL);
        DWORD Ordinal = ExportDirectory->Base + OrdinalTableBase[i];
        ULONG FunctionRVA = FunctionsTableBase[OrdinalTableBase[i]];//Ordinal - 1 == Ordinal - ExportDirectory->Base

        if (FunctionRVA >= DataDirectory.VirtualAddress && FunctionRVA < DataDirectory.VirtualAddress + DataDirectory.Size) {
            PCHAR forwarded = (PCHAR)ImageRvaToVa(NtHeaders, Data, FunctionRVA, NULL);

            printf("hint:%04d, Ordinal:%04d, FunctionRVA:%#010X, ApiName:%s, Forwarded:%s.\r\n",
                   i + 1, Ordinal, FunctionRVA, ApiName != NULL ? ApiName : "(无效)", forwarded != NULL ? forwarded : "(无效)");
        } else {
            printf("hint:%04d, Ordinal:%04d, FunctionRVA:%#010X, ApiName:%s.\r\n",
                   i + 1, Ordinal, FunctionRVA, ApiName != NULL ? ApiName : "(无效)");
        }
    }

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Export(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Export);
}
