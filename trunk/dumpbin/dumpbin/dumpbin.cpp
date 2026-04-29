// dumpbin.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。


#include "pch.h"
#include "log.h"
#include "Architecture.h"
#include "BaseReloc.h"
#include "BoundImport.h"
#include "ComDescriptor.h"
#include "Debug.h"
#include "DelayImport.h"
#include "Exception.h"
#include "Export.h"
#include "Globalptr.h"
#include "IAT.h"
#include "Import.h"
#include "LoadConfig.h"
#include "PeHeader.h"
#include "Resource.h"
#include "Security.h"
#include "TLS.h"
#include "PrintBinary.h"
#include "Disasm.h"
#include "SaveFile.h"
#include "coff.h"


//////////////////////////////////////////////////////////////////////////////////////////////////
// 命令分发表


typedef DWORD (*FileCommandFn)(_In_ LPCWSTR FileName);

// 用于 Usage 提示的命令名 + 描述
struct FileCommandHelp {
    LPCTSTR Name;
    LPCSTR  Description;
};

static const FileCommandHelp g_fileCommandHelp[] = {
    { TEXT("DosHeader"),      "View DosHeader" },
    { TEXT("FileHeader"),     "View FileHeader" },
    { TEXT("OptionalHeader"), "View OptionalHeader" },
    { TEXT("DataDirectory"),  "View DataDirectory" },
    { TEXT("SectionHeader"),  "View SectionHeader" },
    { TEXT("Export"),         "View Export" },
    { TEXT("Import"),         "View Import" },
    { TEXT("Resource"),       "View Resource" },
    { TEXT("Exception"),      "View Exception" },
    { TEXT("Security"),       "View Security" },
    { TEXT("BaseReloc"),      "View BaseReloc" },
    { TEXT("Debug"),          "View Debug" },
    { TEXT("Architecture"),   "View Architecture" },
    { TEXT("Globalptr"),      "View Globalptr" },
    { TEXT("TLS"),            "View TLS" },
    { TEXT("LoadConfig"),     "View LoadConfig" },
    { TEXT("BoundImport"),    "View BoundImport" },
    { TEXT("IAT"),            "View IAT" },
    { TEXT("DelayImport"),    "View DelayImport" },
    { TEXT("ComDescriptor"),  "View ComDescriptor" },
    { TEXT("COFF"),           "View Common Object File Format (COFF) files" },
};

// "命令名 -> 函数" 映射表
struct FileCommandEntry {
    LPCTSTR       Name;
    FileCommandFn Fn;
};

static const FileCommandEntry g_fileCommandTable[] = {
    { TEXT("DosHeader"),       DosHeader },
    { TEXT("FileHeader"),      FileHeader },
    { TEXT("OptionalHeader"),  OptionalHeader },
    // 兼容旧拼写
    { TEXT("OptionlHeader"),   OptionalHeader },
    { TEXT("DataDirectory"),   DataDirectory },
    { TEXT("SectionHeader"),   SectionHeader },
    { TEXT("Export"),          Export },
    { TEXT("Import"),          Import },
    { TEXT("Resource"),        Resource },
    { TEXT("Exception"),       Exception },
    { TEXT("Security"),        Security },
    { TEXT("BaseReloc"),       BaseReloc },
    { TEXT("Debug"),           Debug },
    { TEXT("Architecture"),    Architecture },
    { TEXT("Globalptr"),       Globalptr },
    { TEXT("TLS"),             TLS },
    { TEXT("LoadConfig"),      LoadConfig },
    { TEXT("BoundImport"),     BoundImport },
    { TEXT("IAT"),             IAT },
    { TEXT("DelayImport"),     DelayImport },
    { TEXT("ComDescriptor"),   ComDescriptor },
    { TEXT("COFF"),            coff },
};


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID Usage(TCHAR * exe)
//
// 打印用法。
//
{
    printf("本程序的用法如下：\r\n");
    printf("用法概要：\"%ls\" 命令 文件 选项 ...\r\n", exe);
    printf("\r\n");

    for (size_t i = 0; i < _countof(g_fileCommandHelp); ++i) {
        printf("%s：\"%ls\" %ls FileFullPath\r\n", g_fileCommandHelp[i].Description, exe, g_fileCommandHelp[i].Name);
    }

    printf("View content：\"%ls\" PrintBinary FileFullPath Address(RVA) Length(非负的十进制)\r\n", exe);
    printf("Disassemble(Zydis引擎)：\"%ls\" Disassemble FileFullPath Address(RVA) Length(非负的十进制)\r\n", exe);
    printf("SaveFile：\"%ls\" SaveFile FileFullPath Address(RVA) Length(非负的十进制) NewFileFullPath\r\n", exe);

    printf("\r\n");
    printf("Made by correy\r\n");
    printf("112426112@qq.com\r\n");
    printf("https://correy.webs.com\r\n");
}


static FileCommandFn FindFileCommand(LPCTSTR name)
{
    for (size_t i = 0; i < _countof(g_fileCommandTable); ++i) {
        if (lstrcmpi(name, g_fileCommandTable[i].Name) == 0) {
            return g_fileCommandTable[i].Fn;
        }
    }
    return NULL;
}


void Initialize()
{
    setlocale(LC_CTYPE, ".936"); // 解决汉字显示的问题。
    InitializeCriticalSection(&g_log_cs);
}


void Cleanup()
{
    DeleteCriticalSection(&g_log_cs);
}


int _cdecl wmain(_In_ int argc, _In_reads_(argc) TCHAR * argv[])
{
    int ret = ERROR_SUCCESS;

    Initialize();

    switch (argc) {
    case 3:
    {
        FileCommandFn fn = FindFileCommand(argv[1]);
        if (fn) {
            ret = fn(argv[2]);
        } else {
            Usage(argv[0]);
            ret = ERROR_INVALID_PARAMETER;
        }
        break;
    }
    case 5:
    {
        if (lstrcmpi(argv[1], TEXT("PrintBinary")) == 0) {
            ret = PrintBinary(argv[2], argv[3], argv[4]);
        } else if (lstrcmpi(argv[1], TEXT("Disassemble")) == 0) {
            ret = Disassemble(argv[2], argv[3], argv[4]);
        } else {
            Usage(argv[0]);
            ret = ERROR_INVALID_PARAMETER;
        }
        break;
    }
    case 6:
    {
        if (lstrcmpi(argv[1], TEXT("SaveFile")) == 0) {
            ret = SaveFile(argv[2], argv[3], argv[4], argv[5]);
        } else {
            Usage(argv[0]);
            ret = ERROR_INVALID_PARAMETER;
        }
        break;
    }
    default:
        Usage(argv[0]);
        break;
    }

    Cleanup();
    return ret;
}
