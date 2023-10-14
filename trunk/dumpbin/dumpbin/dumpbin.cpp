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


VOID Usage(TCHAR * exe)
/*++
Routine Description
    Prints usage
--*/
{
    printf("本程序的用法如下：\r\n");
    printf("用法概要：\"%ls\" 命令 文件 选项 ...\r\n", exe);
    printf("\r\n");

    printf("View DosHeader：\"%ls\" DosHeader FileFullPath\r\n", exe);
    printf("View FileHeader：\"%ls\" FileHeader FileFullPath\r\n", exe);
    printf("View OptionlHeader：\"%ls\" OptionlHeader FileFullPath\r\n", exe);
    printf("View DataDirectory：\"%ls\" DataDirectory FileFullPath\r\n", exe);
    printf("View SectionHeader：\"%ls\" SectionHeader FileFullPath\r\n", exe);

    printf("View Export：\"%ls\" Export FileFullPath\r\n", exe);
    printf("View Import：\"%ls\" Import FileFullPath\r\n", exe);
    printf("View Resource：\"%ls\" Resource FileFullPath\r\n", exe);
    printf("View Exception：\"%ls\" Exception FileFullPath\r\n", exe);
    printf("View Security：\"%ls\" Security FileFullPath\r\n", exe);
    printf("View BaseReloc：\"%ls\" BaseReloc FileFullPath\r\n", exe);
    printf("View Debug：\"%ls\" Debug FileFullPath\r\n", exe);
    printf("View Architecture：\"%ls\" Architecture FileFullPath\r\n", exe);
    printf("View Globalptr：\"%ls\" Globalptr FileFullPath\r\n", exe);
    printf("View TLS：\"%ls\" TLS FileFullPath\r\n", exe);
    printf("View LoadConfig：\"%ls\" LoadConfig FileFullPath\r\n", exe);
    printf("View BoundImport：\"%ls\" BoundImport FileFullPath\r\n", exe);
    printf("View IAT：\"%ls\" IAT FileFullPath\r\n", exe);
    printf("View DelayImport：\"%ls\" DelayImport FileFullPath\r\n", exe);
    printf("View ComDescriptor：\"%ls\" ComDescriptor FileFullPath\r\n", exe);

    printf("View Common Object File Format (COFF) files：\"%ls\" COFF FileFullPath\r\n", exe);

    printf("View content：\"%ls\" PrintBinary FileFullPath Address(RVA) Length(非负的十进制)\r\n", exe);
    printf("Disassemble(Zydis引擎)：\"%ls\" Disassemble FileFullPath Address(RVA) Length(非负的十进制)\r\n", exe);

    printf("SaveFile：\"%ls\" SaveFile FileFullPath Address(RVA) Length(非负的十进制) NewFileFullPath\r\n", exe);

    printf("\r\n");
    printf("Made by correy\r\n");
    printf("112426112@qq.com\r\n");
    printf("https://correy.webs.com\r\n");    
}


void Initialize()
{
    setlocale(LC_CTYPE, ".936");//解决汉字显示的问题。

    InitializeCriticalSection(&g_log_cs);



}


int _cdecl wmain(_In_ int argc, _In_reads_(argc) TCHAR * argv[])
{
    int ret = ERROR_SUCCESS;

    Initialize();

    switch (argc) {
    case 1:
        Usage(argv[0]);
        break;
    case 2:
        Usage(argv[0]);
        break;
    case 3:
    {
        if (lstrcmpi(argv[1], TEXT("DosHeader")) == 0) {
            ret = DosHeader(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("FileHeader")) == 0) {
            ret = FileHeader(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("OptionlHeader")) == 0) {
            ret = OptionlHeader(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("DataDirectory")) == 0) {
            ret = DataDirectory(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("SectionHeader")) == 0) {
            ret = SectionHeader(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Export")) == 0) {
            ret = Export(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Import")) == 0) {
            ret = Import(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Resource")) == 0) {
            ret = Resource(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Exception")) == 0) {
            ret = Exception(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Security")) == 0) {
            ret = Security(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("BaseReloc")) == 0) {
            ret = BaseReloc(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Debug")) == 0) {
            ret = Debug(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Architecture")) == 0) {
            ret = Architecture(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("Globalptr")) == 0) {
            ret = Globalptr(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("TLS")) == 0) {
            ret = TLS(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("LoadConfig")) == 0) {
            ret = LoadConfig(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("BoundImport")) == 0) {
            ret = BoundImport(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("IAT")) == 0) {
            ret = IAT(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("DelayImport")) == 0) {
            ret = DelayImport(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("ComDescriptor")) == 0) {
            ret = ComDescriptor(argv[2]);
        } else if (lstrcmpi(argv[1], TEXT("COFF")) == 0) {
            ret = coff(argv[2]);
        } else {
            Usage(argv[0]);
        }

        break;
    }
    case 4:
    {
        Usage(argv[0]);
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
        }

        break;
    }
    case 6:
    {
        if (lstrcmpi(argv[1], TEXT("SaveFile")) == 0) {
            ret = SaveFile(argv[2], argv[3], argv[4], argv[4]);
        } else {
            Usage(argv[0]);
        }

        break;
    }
    default:
        Usage(argv[0]);
        break;
    }

    return ret;
}
