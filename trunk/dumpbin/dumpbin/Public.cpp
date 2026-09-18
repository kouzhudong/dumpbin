#include "pch.h"
#include "Public.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


struct FlagEntry
{
    DWORD   Flag;
    PCSTR   Name;
};


static void AppendFlags(_In_ DWORD Value, _In_reads_(Count) const FlagEntry * Table, _In_ size_t Count, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
{
    for (size_t i = 0; i < Count; i++) {
        if (Value & Table[i].Flag) {
            StringCchCatA(String, cchDest, Table[i].Name);
        }
    }
}


LPWSTR UTF8ToWide(IN PCHAR utf8)
/*
得到的内存有调用者释放。
*/
{
    int cchWideChar = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, 0, 0);
    if (cchWideChar == 0) {
        return NULL;
    }

    LPWSTR pws = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)cchWideChar * sizeof(WCHAR));
    if (pws == NULL) {
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, pws, cchWideChar) == 0) {//utf8->Unicode
        HeapFree(GetProcessHeap(), 0, pws);
        return NULL;
    }

    return pws;
}


void GetDataDirectory(_In_ PBYTE Data, _In_ DWORD Size, _In_ BYTE index, _Out_ PIMAGE_DATA_DIRECTORY DataDirectory)
{
    DataDirectory->VirtualAddress = 0;
    DataDirectory->Size = 0;

    if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        LOGA(ERROR_LEVEL, "DataDirectory index out of range: %u", index);
        return;
    }

    if (!IsValidPE(Data, Size)) {
        return;
    }

    PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(Data);
    if (NtHeader == NULL) {
        return;
    }

    DWORD data_directory_offset = 0;
    DWORD number_of_rva_and_sizes = 0;
    if (IsPE32Ex(Data, Size)) {
        PIMAGE_OPTIONAL_HEADER64 opt = (PIMAGE_OPTIONAL_HEADER64)&NtHeader->OptionalHeader;
        data_directory_offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        number_of_rva_and_sizes = opt->NumberOfRvaAndSizes;
    } else {
        PIMAGE_OPTIONAL_HEADER32 opt = (PIMAGE_OPTIONAL_HEADER32)&NtHeader->OptionalHeader;
        data_directory_offset = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        number_of_rva_and_sizes = opt->NumberOfRvaAndSizes;
    }

    // NumberOfRvaAndSizes 只是"声明"的项数，还要受可选头实际长度的约束。
    DWORD size_of_optional_header = NtHeader->FileHeader.SizeOfOptionalHeader;
    if (size_of_optional_header < data_directory_offset) {
        LOGA(ERROR_LEVEL, "SizeOfOptionalHeader 过短:%#X", size_of_optional_header);
        return;
    }

    DWORD max_entries = (size_of_optional_header - data_directory_offset) / sizeof(IMAGE_DATA_DIRECTORY);
    if (index >= number_of_rva_and_sizes || index >= max_entries) {
        return;
    }

    PIMAGE_DATA_DIRECTORY directory_entry = (PIMAGE_DATA_DIRECTORY)((PBYTE)&NtHeader->OptionalHeader + data_directory_offset);

    *DataDirectory = directory_entry[index];
}


void GetSectionCharacteristics(_In_ DWORD Characteristics, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
{
    static const FlagEntry SectionFlags[] = {
        {IMAGE_SCN_SCALE_INDEX,              "SCALE_INDEX "},
        {IMAGE_SCN_TYPE_NO_PAD,              "TYPE_NO_PAD "},
        {IMAGE_SCN_CNT_CODE,                 "CNT_CODE "},
        {IMAGE_SCN_CNT_INITIALIZED_DATA,     "INITIALIZED_DATA "},
        {IMAGE_SCN_CNT_UNINITIALIZED_DATA,   "CNT_UNINITIALIZED_DATA "},
        {IMAGE_SCN_LNK_OTHER,                "LNK_OTHER "},
        {IMAGE_SCN_LNK_INFO,                 "LNK_INFO "},
        {IMAGE_SCN_LNK_REMOVE,               "LNK_REMOVE "},
        {IMAGE_SCN_LNK_COMDAT,               "LNK_COMDAT "},
        {IMAGE_SCN_NO_DEFER_SPEC_EXC,        "NO_DEFER_SPEC_EXC "},
        {IMAGE_SCN_GPREL,                    "GPREL "},
        {IMAGE_SCN_MEM_FARDATA,              "MEM_FARDATA "},
        {IMAGE_SCN_MEM_PURGEABLE,            "MEM_PURGEABLE "},
        {IMAGE_SCN_MEM_LOCKED,               "MEM_LOCKED "},
        {IMAGE_SCN_MEM_PRELOAD,              "MEM_PRELOAD "},
        {IMAGE_SCN_LNK_NRELOC_OVFL,          "LNK_NRELOC_OVFL "},
        {IMAGE_SCN_MEM_DISCARDABLE,          "MEM_DISCARDABLE "},
        {IMAGE_SCN_MEM_NOT_CACHED,           "MEM_NOT_CACHED "},
        {IMAGE_SCN_MEM_NOT_PAGED,            "MEM_NOT_PAGED "},
        {IMAGE_SCN_MEM_SHARED,               "MEM_SHARED "},
        {IMAGE_SCN_MEM_EXECUTE,              "MEM_EXECUTE "},
        {IMAGE_SCN_MEM_READ,                 "MEM_READ "},
        {IMAGE_SCN_MEM_WRITE,                "MEM_WRITE "},
    };

    AppendFlags(Characteristics, SectionFlags, _countof(SectionFlags), String, cchDest);

    // IMAGE_SCN_ALIGN_* is a 4-bit field, not independent bit flags.
    static const PCSTR AlignNames[] = {
        NULL,               // 0: default
        "ALIGN_1BYTES ",    // 1
        "ALIGN_2BYTES ",    // 2
        "ALIGN_4BYTES ",    // 3
        "ALIGN_8BYTES ",    // 4
        "ALIGN_16BYTES ",   // 5
        "ALIGN_32BYTES ",   // 6
        "ALIGN_64BYTES ",   // 7
        "ALIGN_128BYTES ",  // 8
        "ALIGN_256BYTES ",  // 9
        "ALIGN_512BYTES ",  // 10
        "ALIGN_1024BYTES ", // 11
        "ALIGN_2048BYTES ", // 12
        "ALIGN_4096BYTES ", // 13
        "ALIGN_8192BYTES ", // 14
        NULL,               // 15: reserved
    };

    DWORD alignIndex = (Characteristics & IMAGE_SCN_ALIGN_MASK) >> 20;
    if (alignIndex < _countof(AlignNames) && AlignNames[alignIndex] != NULL) {
        StringCchCatA(String, cchDest, AlignNames[alignIndex]);
    }
}


void GetDllCharacteristics(_In_ WORD Characteristics, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
{
    static const FlagEntry DllFlags[] = {
        {IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,       "HIGH_ENTROPY_VA "},
        {IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,          "DYNAMIC_BASE "},
        {IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,       "FORCE_INTEGRITY "},
        {IMAGE_DLLCHARACTERISTICS_NX_COMPAT,             "NX_COMPAT "},
        {IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,          "NO_ISOLATION "},
        {IMAGE_DLLCHARACTERISTICS_NO_SEH,                "NO_SEH "},
        {IMAGE_DLLCHARACTERISTICS_NO_BIND,               "NO_BIND "},
        {IMAGE_DLLCHARACTERISTICS_APPCONTAINER,          "APPCONTAINER "},
        {IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,            "WDM_DRIVER "},
        {IMAGE_DLLCHARACTERISTICS_GUARD_CF,              "GUARD_CF "},
        {IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVER_AWARE "},
    };

    AppendFlags(Characteristics, DllFlags, _countof(DllFlags), String, cchDest);
}


PCSTR GetSubsystem(_In_ WORD Subsystem)
{
    struct SubsystemEntry
    {
        WORD    Value;
        PCSTR   Name;
    };

    static const SubsystemEntry Table[] = {
        {IMAGE_SUBSYSTEM_UNKNOWN,                  "UNKNOWN"},
        {IMAGE_SUBSYSTEM_NATIVE,                   "NATIVE"},
        {IMAGE_SUBSYSTEM_WINDOWS_GUI,              "WINDOWS_GUI"},
        {IMAGE_SUBSYSTEM_WINDOWS_CUI,              "WINDOWS_CUI"},
        {IMAGE_SUBSYSTEM_OS2_CUI,                  "OS2_CUI"},
        {IMAGE_SUBSYSTEM_POSIX_CUI,                "POSIX_CUI"},
        {IMAGE_SUBSYSTEM_NATIVE_WINDOWS,           "NATIVE_WINDOWS"},
        {IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,           "WINDOWS_CE_GUI"},
        {IMAGE_SUBSYSTEM_EFI_APPLICATION,          "EFI_APPLICATION"},
        {IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,  "EFI_BOOT_SERVICE_DRIVER"},
        {IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,       "EFI_RUNTIME_DRIVER"},
        {IMAGE_SUBSYSTEM_EFI_ROM,                  "EFI_ROM"},
        {IMAGE_SUBSYSTEM_XBOX,                     "XBOX"},
        {IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, "WINDOWS_BOOT_APPLICATION"},
        {IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG,        "XBOX_CODE_CATALOG"},
    };

    for (size_t i = 0; i < _countof(Table); i++) {
        if (Table[i].Value == Subsystem) {
            return Table[i].Name;
        }
    }

    LOGA(ERROR_LEVEL, "SUBSYSTEM:%#X", Subsystem);
    return "未定义";
}


void TimeStampToFileTime(INT64 timeStamp, FILETIME & fileTime)
{
    static const INT64 TICKS_PER_SECOND = 10000000LL;
    static const INT64 EPOCH_DIFFERENCE = 116444736000000000LL; // 1601-01-01 to 1970-01-01

    INT64 ticks = timeStamp * TICKS_PER_SECOND + EPOCH_DIFFERENCE;
    fileTime.dwLowDateTime = (DWORD)ticks;
    fileTime.dwHighDateTime = (DWORD)(ticks >> 32);
}


void FileTimeToLocalTimeA(PFILETIME ft, char * time)
/*
把FileTime转换为本地时间打印。
*/
{
    if (ft == NULL || time == NULL) {
        return;
    }

    FILETIME lft = {0};
    SYSTEMTIME st = {0};

    if (!FileTimeToLocalFileTime(ft, &lft) || !FileTimeToSystemTime(&lft, &st)) {
        StringCchCopyA(time, MAX_PATH, "未知");
        return;
    }

    //格式：2016-07-11 17:35:54
    wsprintfA(time, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}


void GetTimeDateStamp(_In_ DWORD TimeDateStamp, _Out_writes_(MAX_PATH) PCHAR String)
{
    FILETIME FileTime = {0};
    TimeStampToFileTime(TimeDateStamp, FileTime);

    FileTimeToLocalTimeA(&FileTime, String);
}


void GetCharacteristics(_In_ WORD Characteristics, _Out_writes_(cchDest) PCHAR String, _In_ size_t cchDest)
{
    static const FlagEntry FileFlags[] = {
        {IMAGE_FILE_RELOCS_STRIPPED,         "RELOCS_STRIPPED "},
        {IMAGE_FILE_EXECUTABLE_IMAGE,        "EXECUTABLE_IMAGE "},
        {IMAGE_FILE_LINE_NUMS_STRIPPED,       "LINE_NUMS_STRIPPED "},
        {IMAGE_FILE_LOCAL_SYMS_STRIPPED,      "LOCAL_SYMS_STRIPPED "},
        {IMAGE_FILE_AGGRESIVE_WS_TRIM,       "AGGRESIVE_WS_TRIM "},
        {IMAGE_FILE_LARGE_ADDRESS_AWARE,      "LARGE_ADDRESS_AWARE "},
        {IMAGE_FILE_BYTES_REVERSED_LO,        "BYTES_REVERSED_LO "},
        {IMAGE_FILE_32BIT_MACHINE,            "32BIT_MACHINE "},
        {IMAGE_FILE_DEBUG_STRIPPED,            "DEBUG_STRIPPED "},
        {IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,  "REMOVABLE_RUN_FROM_SWAP "},
        {IMAGE_FILE_NET_RUN_FROM_SWAP,        "NET_RUN_FROM_SWAP "},
        {IMAGE_FILE_SYSTEM,                   "SYSTEM "},
        {IMAGE_FILE_DLL,                      "DLL "},
        {IMAGE_FILE_UP_SYSTEM_ONLY,           "UP_SYSTEM_ONLY "},
        {IMAGE_FILE_BYTES_REVERSED_HI,        "BYTES_REVERSED_HI "},
    };

    _ASSERTE(String);

    AppendFlags(Characteristics, FileFlags, _countof(FileFlags), String, cchDest);
}


PCSTR GetMachine(_In_ WORD Machine)
{
    struct MachineEntry
    {
        WORD    Value;
        PCSTR   Name;
    };

    static const MachineEntry Table[] = {
        {IMAGE_FILE_MACHINE_UNKNOWN,    "适用于任何类型处理器"},
        {IMAGE_FILE_MACHINE_TARGET_HOST,"Useful for indicating we want to interact with the host and not a WoW guest"},
        {IMAGE_FILE_MACHINE_I386,       "Intel 386"},
        {IMAGE_FILE_MACHINE_R3000,      "MIPS little-endian, 0x160 big-endian"},
        {IMAGE_FILE_MACHINE_R4000,      "MIPS little-endian"},
        {IMAGE_FILE_MACHINE_R10000,     "MIPS little-endian"},
        {IMAGE_FILE_MACHINE_WCEMIPSV2,  "MIPS little-endian WCE v2"},
        {IMAGE_FILE_MACHINE_ALPHA,      "Alpha_AXP"},
        {IMAGE_FILE_MACHINE_SH3,        "SH3 little-endian"},
        {IMAGE_FILE_MACHINE_SH3DSP,     "IMAGE_FILE_MACHINE_SH3DSP"},
        {IMAGE_FILE_MACHINE_SH3E,       "SH3E little-endian"},
        {IMAGE_FILE_MACHINE_SH4,        "SH4 little-endian"},
        {IMAGE_FILE_MACHINE_SH5,        "SH5"},
        {IMAGE_FILE_MACHINE_ARM,        "ARM Little-Endian"},
        {IMAGE_FILE_MACHINE_THUMB,      "ARM Thumb/Thumb-2 Little-Endian"},
        {IMAGE_FILE_MACHINE_ARMNT,      "ARM Thumb-2 Little-Endian"},
        {IMAGE_FILE_MACHINE_AM33,       "IMAGE_FILE_MACHINE_AM33"},
        {IMAGE_FILE_MACHINE_POWERPC,    "IBM PowerPC Little-Endian"},
        {IMAGE_FILE_MACHINE_POWERPCFP,  "IMAGE_FILE_MACHINE_POWERPCFP"},
        {IMAGE_FILE_MACHINE_IA64,       "Intel 64"},
        {IMAGE_FILE_MACHINE_MIPS16,     "MIPS"},
        {IMAGE_FILE_MACHINE_ALPHA64,    "ALPHA64"},
        {IMAGE_FILE_MACHINE_MIPSFPU,    "MIPS"},
        {IMAGE_FILE_MACHINE_MIPSFPU16,  "MIPS"},
        {IMAGE_FILE_MACHINE_TRICORE,    "Infineon"},
        {IMAGE_FILE_MACHINE_CEF,        "IMAGE_FILE_MACHINE_CEF"},
        {IMAGE_FILE_MACHINE_EBC,        "EFI Byte Code"},
        {IMAGE_FILE_MACHINE_AMD64,      "AMD64 (K8)"},
        {IMAGE_FILE_MACHINE_M32R,       "M32R little-endian"},
        {IMAGE_FILE_MACHINE_ARM64,      "ARM64 Little-Endian"},
        {IMAGE_FILE_MACHINE_CEE,        "IMAGE_FILE_MACHINE_CEE"},
    };

    for (size_t i = 0; i < _countof(Table); i++) {
        if (Table[i].Value == Machine) {
            return Table[i].Name;
        }
    }

    LOGA(ERROR_LEVEL, "Machine:%#X", Machine);
    return "未知";
}


BOOL IsWow64()
{
#ifdef _WIN64
    return FALSE;
#else
    BOOL bIsWow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &bIsWow64)) {
        bIsWow64 = FALSE;
    }
    return bIsWow64;
#endif
}


bool IsValidPE(_In_ PBYTE Data, _In_ DWORD Size)
{
    bool ret = false;

    __try {
        if (Data == NULL || Size < sizeof(IMAGE_DOS_HEADER)) {
            LOGA(ERROR_LEVEL, "文件过小或数据为空, Size:%u", Size);
            __leave;
        }

        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Data;
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            LOGA(ERROR_LEVEL, "e_magic:%#X, 不是有效的DOS头", DosHeader->e_magic);
            __leave;
        }

        // e_lfanew 是 NT 头相对文件起始的偏移，必须落在文件内。
        if (DosHeader->e_lfanew < 0 ||
            (DWORD)DosHeader->e_lfanew > Size - sizeof(DWORD) - sizeof(IMAGE_FILE_HEADER)) {
            LOGA(ERROR_LEVEL, "e_lfanew 越界:%#X, Size:%u", DosHeader->e_lfanew, Size);
            __leave;
        }

        PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(Data + DosHeader->e_lfanew);

        // 可选头和节表也必须在文件内，否则后续按结构体偏移读取会越界。
        DWORD section_table_offset = (DWORD)DosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + NtHeader->FileHeader.SizeOfOptionalHeader;
        if (section_table_offset > Size ||
            Size - section_table_offset < (DWORD)NtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) {
            LOGA(ERROR_LEVEL, "节表越界, 偏移:%#X, 节数:%u, Size:%u", section_table_offset, NtHeader->FileHeader.NumberOfSections, Size);
            __leave;
        }

        // 每个节的原始数据也要落在文件内，否则按 RVA 换算出的偏移会越过文件尾(截断的文件会命中这里)。
        PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)(Data + section_table_offset);
        for (WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
            if (SectionHeader[i].SizeOfRawData == 0) {
                continue;//.bss 这类节没有文件数据。
            }

            if (SectionHeader[i].PointerToRawData > Size || SectionHeader[i].SizeOfRawData > Size - SectionHeader[i].PointerToRawData) {
                LOGA(ERROR_LEVEL, "节数据越界, 第%u节, 偏移:%#X, 大小:%#X, Size:%u",
                     i + 1, SectionHeader[i].PointerToRawData, SectionHeader[i].SizeOfRawData, Size);
                __leave;
            }
        }

        switch (NtHeader->Signature) {
        case IMAGE_OS2_SIGNATURE:
            LOGA(ERROR_LEVEL, "恭喜你:发现一个NE文件!");
            break;
        case IMAGE_OS2_SIGNATURE_LE://IMAGE_VXD_SIGNATURE
            LOGA(ERROR_LEVEL, "恭喜你:发现一个LE文件!");
            break;
        case IMAGE_NT_SIGNATURE:
            // 可选头必须存在才能读 Magic，且 Magic 必须是 PE32/PE32+，否则后面的按位解析全是错的。
            if (NtHeader->FileHeader.SizeOfOptionalHeader < sizeof(WORD)) {
                LOGA(ERROR_LEVEL, "SizeOfOptionalHeader 过短:%#X", NtHeader->FileHeader.SizeOfOptionalHeader);
                break;
            }

            switch (((PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader)->Magic) {
            case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
                LOGA(ERROR_LEVEL, "恭喜你:发现一个ROM映像!");
                break;
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                ret = true;
                break;
            default:
                LOGA(ERROR_LEVEL, "Magic:%#X!", ((PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader)->Magic);
                break;
            }
            break;
        default:
            LOGA(ERROR_LEVEL, "Signature:%#X", NtHeader->Signature);
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD ExceptionCode = GetExceptionCode();
        LOGA(ERROR_LEVEL, "ExceptionCode:%#x", ExceptionCode);
        ret = false;
    }

    return ret;
}


bool IsPE32Ex(_In_ PBYTE Data, _In_ DWORD Size)
{
    bool ret = false;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(Data);
    if (NtHeader == NULL) {
        return ret;
    }

    /*
    对于可选头的标准域(排除最后一个BaseOfData)来说，是32位的可选头和64位的可选头无所谓，因为偏移都是一样的。
    */
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
    if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == OptionalHeader->Magic) {
        ret = true;//这是一个的PE32+文件
    }

    return ret;
}


void GetSectionName(_In_ PIMAGE_SECTION_HEADER SectionHeader, _Out_writes_(IMAGE_SIZEOF_SHORT_NAME + 1) PCHAR String)
{
    CopyMemory(String, SectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME);
    String[IMAGE_SIZEOF_SHORT_NAME] = '\0';
}


// 当前正在解析的文件名，供回调函数取用（见 GetCurrentFileName）。
static thread_local LPCWSTR g_current_file_name = NULL;


LPCWSTR GetCurrentFileName()
{
    return g_current_file_name;
}


DWORD MapFile(_In_ LPCWSTR FileName, _In_opt_ PeCallBack CallBack)
{
    DWORD LastError = ERROR_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapFile = NULL;
    PBYTE FileContent = NULL;
    PVOID Wow64OldValue = NULL;
    BOOL Wow64FsRedirectionDisabled = FALSE;

    if (FileName == NULL || FileName[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }

    if (IsWow64()) {//在wow64下关闭文件重定向。
        //失败也没关系，只是继续走重定向而已。
        Wow64FsRedirectionDisabled = Wow64DisableWow64FsRedirection(&Wow64OldValue);
    }

    __try {
        hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFile");
            __leave;
        }

        LARGE_INTEGER FileSize = {0};
        if (!GetFileSizeEx(hFile, &FileSize)) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("GetFileSizeEx");
            __leave;
        }

        if (FileSize.QuadPart == 0) {
            LastError = ERROR_EMPTY;
            LOGA(ERROR_LEVEL, "file is empty");
            __leave;
        }

        if (FileSize.HighPart != 0) {//暂时不支持大于4G的文件。
            LastError = ERROR_FILE_TOO_LARGE;
            LOGA(ERROR_LEVEL, "file too large: %llu bytes", FileSize.QuadPart);
            __leave;
        }

        hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMapFile == NULL) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("CreateFileMapping");
            __leave;
        }

        FileContent = (PBYTE)MapViewOfFile(hMapFile, SECTION_MAP_READ, 0, 0, 0);
        if (FileContent == NULL) {
            LastError = GetLastError();
            LOGA(ERROR_LEVEL, "LastError:%#d", LastError);
            LogApiErrMsg("MapViewOfFile");
            __leave;
        }

        if (CallBack) {
            g_current_file_name = FileName;
            __try {
                LastError = CallBack(FileContent, FileSize.LowPart);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                LastError = GetExceptionCode();
                LOGA(ERROR_LEVEL, "ExceptionCode:%#x", LastError);
            }
        }
    } __finally {
        g_current_file_name = NULL;

        if (FileContent) {
            UnmapViewOfFile(FileContent);
        }

        if (hMapFile) {
            CloseHandle(hMapFile);
        }

        if (INVALID_HANDLE_VALUE != hFile) {
            CloseHandle(hFile);
        }

        if (Wow64FsRedirectionDisabled) {
            Wow64RevertWow64FsRedirection(Wow64OldValue);
        }
    }

    return LastError;
}
