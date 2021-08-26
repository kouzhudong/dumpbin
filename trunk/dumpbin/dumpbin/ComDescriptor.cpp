#include "pch.h"
#include "ComDescriptor.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void MetaData(PVOID Address, DWORD Size)
{


}


void Resources(PVOID Address, DWORD Size)
{


}


void StrongNameSignature(PVOID Address, DWORD Size)
{


}


void CodeManagerTable(PVOID Address, DWORD Size)
{


}


void VTableFixups(PVOID Address, DWORD Size)
{


}


void ExportAddressTableJumps(PVOID Address, DWORD Size)
{


}


void ManagedNativeHeader(PVOID Address, DWORD Size)
{


}


DWORD ComDescriptor(_In_ PBYTE Data, _In_ DWORD Size)
/*

The .NET Header
Executables produced for the Microsoft .NET environment are first and foremost PE files.
However, in most cases normal code and data in a .NET file are minimal.
The primary purpose of a .NET executable is to get the .NET-specific information such as metadata and intermediate language (IL) into memory.
In addition, a .NET executable links against MSCOREE.DLL.
This DLL is the starting point for a .NET process.
When a .NET executable loads, its entry point is usually a tiny stub of code.
That stub just jumps to an exported function in MSCOREE.DLL (_CorExeMain or _CorDllMain).
From there, MSCOREE takes charge, and starts using the metadata and IL from the executable file.
This setup is similar to the way apps in Visual Basic (prior to .NET) used MSVBVM60.DLL.
The starting point for .NET information is the IMAGE_COR20_HEADER structure, currently defined in CorHDR.H from the .NET Framework SDK and more recent versions of WINNT.H.
The IMAGE_COR20_HEADER is pointed to by the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR entry in the DataDirectory.
Figure 10 shows the fields of an IMAGE_COR20_HEADER.
The format of the metadata, method IL, and other things pointed to by the IMAGE_COR20_HEADER will be described in a subsequent article.

参考：
1.\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\rtl\lookup.c的RtlCaptureImageExceptionValues
2.https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
3.https://github.com/zodiacon/PEExplorerV2.git
4.PEBrowse
5.https://www.codeproject.com/Articles/12585/The-NET-File-Format
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有ComDescriptor.\r\n");
        return ret;
    }

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);

    //////////////////////////////////////////////////////////////////////////////////////////////////

    ULONG size = 0;
    PIMAGE_SECTION_HEADER FoundHeader = NULL;
    PIMAGE_COR20_HEADER ComDescriptorDirectory = (PIMAGE_COR20_HEADER)
        ImageDirectoryEntryToDataEx(Data,
                                    FALSE,//自己映射的用FALSE，操作系统加载的用TRUE。 
                                    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
                                    &size, &FoundHeader);

    printf("Com Descriptor Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    if (FoundHeader) {
        printf("SectionName:%s.\r\n", FoundHeader->Name);
    }

    printf("\r\n");

    //////////////////////////////////////////////////////////////////////////////////////////////////

    printf("cb:%#010X.\r\n", ComDescriptorDirectory->cb);
    printf("RuntimeVersion:%d.%d.\r\n",
           ComDescriptorDirectory->MajorRuntimeVersion, ComDescriptorDirectory->MinorRuntimeVersion);

    printf("MetaData VirtualAddress:%#010X, Size:%#010X.\r\n",
           ComDescriptorDirectory->MetaData.VirtualAddress, ComDescriptorDirectory->MetaData.Size);

    printf("Flags:%#010X.\r\n", ComDescriptorDirectory->Flags);

    if (COMIMAGE_FLAGS_NATIVE_ENTRYPOINT & ComDescriptorDirectory->Flags) {
        printf("EntryPointRVA:%#010X.\r\n", ComDescriptorDirectory->EntryPointRVA);
    } else {
        printf("EntryPointToken:%#010X.\r\n", ComDescriptorDirectory->EntryPointToken);
    }

    printf("Resources VirtualAddress:%#010X, Size:%#010X.\r\n",
           ComDescriptorDirectory->Resources.VirtualAddress,
           ComDescriptorDirectory->Resources.Size);

    printf("StrongNameSignature VirtualAddress:%#010X, Size:%#010X.\r\n",
           ComDescriptorDirectory->StrongNameSignature.VirtualAddress,
           ComDescriptorDirectory->StrongNameSignature.Size);

    printf("CodeManagerTable VirtualAddress:%#010X, Size:%#010X.\r\n",
           ComDescriptorDirectory->CodeManagerTable.VirtualAddress,
           ComDescriptorDirectory->CodeManagerTable.Size);

    printf("VTableFixups VirtualAddress:%#010X, Size:%#010X.\r\n",
           ComDescriptorDirectory->VTableFixups.VirtualAddress, 
           ComDescriptorDirectory->VTableFixups.Size);

    printf("ExportAddressTableJumps VirtualAddress:%#010X, Size:%#010X.\r\n",
           ComDescriptorDirectory->ExportAddressTableJumps.VirtualAddress,
           ComDescriptorDirectory->ExportAddressTableJumps.Size);

    printf("ManagedNativeHeader VirtualAddress:%#010X, Size:%#010X.\r\n",
           ComDescriptorDirectory->ManagedNativeHeader.VirtualAddress, 
           ComDescriptorDirectory->ManagedNativeHeader.Size);

    //////////////////////////////////////////////////////////////////////////////////////////////////

    PVOID MetaDataVirtualAddress = NULL;
    if (ComDescriptorDirectory->MetaData.VirtualAddress) {
        MetaDataVirtualAddress = ImageRvaToVa(NtHeaders, Data, ComDescriptorDirectory->MetaData.VirtualAddress, NULL);
        MetaData(MetaDataVirtualAddress, ComDescriptorDirectory->MetaData.Size);
    }

    PVOID ResourcesVirtualAddress = NULL;
    if (ComDescriptorDirectory->Resources.VirtualAddress) {
        ResourcesVirtualAddress = ImageRvaToVa(NtHeaders, Data, ComDescriptorDirectory->Resources.VirtualAddress, NULL);
        Resources(ResourcesVirtualAddress, ComDescriptorDirectory->Resources.Size);
    }

    PVOID StrongNameSignatureVirtualAddress = NULL;
    if (ComDescriptorDirectory->StrongNameSignature.VirtualAddress) {
        StrongNameSignatureVirtualAddress = 
            ImageRvaToVa(NtHeaders, Data, ComDescriptorDirectory->StrongNameSignature.VirtualAddress, NULL);
        StrongNameSignature(StrongNameSignatureVirtualAddress, ComDescriptorDirectory->StrongNameSignature.Size);
    }

    PVOID CodeManagerTableVirtualAddress = NULL;
    if (ComDescriptorDirectory->CodeManagerTable.VirtualAddress) {
        CodeManagerTableVirtualAddress = 
            ImageRvaToVa(NtHeaders, Data, ComDescriptorDirectory->CodeManagerTable.VirtualAddress, NULL);
        CodeManagerTable(CodeManagerTableVirtualAddress, ComDescriptorDirectory->CodeManagerTable.Size);
    }

    PVOID VTableFixupsVirtualAddress = NULL;
    if (ComDescriptorDirectory->VTableFixups.VirtualAddress) {
        VTableFixupsVirtualAddress = 
            ImageRvaToVa(NtHeaders, Data, ComDescriptorDirectory->VTableFixups.VirtualAddress, NULL);
        VTableFixups(VTableFixupsVirtualAddress, ComDescriptorDirectory->VTableFixups.Size);
    }

    PVOID ExportAddressTableJumpsVirtualAddress = NULL;
    if (ComDescriptorDirectory->ExportAddressTableJumps.VirtualAddress) {
        ExportAddressTableJumpsVirtualAddress = 
            ImageRvaToVa(NtHeaders, Data, ComDescriptorDirectory->ExportAddressTableJumps.VirtualAddress, NULL);
        ExportAddressTableJumps(ExportAddressTableJumpsVirtualAddress, ComDescriptorDirectory->ExportAddressTableJumps.Size);
    }

    PVOID ManagedNativeHeaderVirtualAddress = NULL;
    if (ComDescriptorDirectory->ManagedNativeHeader.VirtualAddress) {
        ManagedNativeHeaderVirtualAddress =
            ImageRvaToVa(NtHeaders, Data, ComDescriptorDirectory->ManagedNativeHeader.VirtualAddress, NULL);
        ManagedNativeHeader(ManagedNativeHeaderVirtualAddress, ComDescriptorDirectory->ManagedNativeHeader.Size);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD ComDescriptor(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, ComDescriptor);
}
