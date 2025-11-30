#include "import.h"
#include "pe32+.h"

extern bool g_IsPE32Ex;//是一个PE32+文件吗?
extern HTREEITEM g_htreeitem_data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//预先分配这么多,实际的不会超过这个数
extern HWND g_h_tree;//唯一的一个树形控件的句柄.
extern HTREEITEM g_htreeitem[EXPLAIN + 1];//存储树形控件的已知的数量的变量.
extern wchar_t * g_table_name[];
extern HWND g_h_edit_FilePath;//显示文件路径用的.

//导入表的DLL名字的树形控件的句柄，暂时设置最多为２６０.
HTREEITEM h_tree_import_dllname[260] = {0};

unsigned int RVATOOFFSET(IN wchar_t * filename, IN unsigned int rva)
/*
返回０表示失败，其他的是在文件中的偏移。
*/
{
    unsigned int offset = 0;//返回值。

    HANDLE hfile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD FileSizeHigh;
    DWORD FileSizeLow = GetFileSize(hfile, &FileSizeHigh);
    DWORD64 filesize = FileSizeHigh * 0x100000000 + FileSizeLow;

    if (FileSizeLow == 0 && FileSizeHigh == 0) {//如果文件大小为0.
        CloseHandle(hfile);
        return false;
    }

    HANDLE hfilemap = CreateFileMapping(hfile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* 空文件则返回失败 */
    if (hfilemap == NULL) {
        CloseHandle(hfile);
        return false;
    }

    LPVOID pmz = MapViewOfFile(hfilemap, SECTION_MAP_READ, NULL, NULL, 0/*映射所有*/);//暂时不支持大于4G的文件。
    if (pmz == NULL) {
        CloseHandle(hfilemap);
        CloseHandle(hfile);
        return false;
    }

    IMAGE_DOS_HEADER * p_image_dos_header = (IMAGE_DOS_HEADER *)pmz;
    if (IMAGE_DOS_SIGNATURE != p_image_dos_header->e_magic) {
        UnmapViewOfFile(pmz);
        CloseHandle(hfilemap);
        CloseHandle(hfile);
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
        UnmapViewOfFile(pmz);
        CloseHandle(hfilemap);
        CloseHandle(hfile);
        return false;
    }

    DWORD  CoffHeaderOffset = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew + sizeof(ULONG);
    IMAGE_FILE_HEADER * p_image_file_header = (IMAGE_FILE_HEADER *)CoffHeaderOffset;

    //注意这里用的永远是:IMAGE_OPTIONAL_HEADER32.
    //要分析IMAGE_OPTIONAL_HEADER64的一个办法是:强制定义一个,载赋值转换.
    //其实这个结构的大小是固定的,只不过32位的和64位的不一样.但还是用规范建议的.IMAGE_FILE_HEADER的成员访问好.
    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    IMAGE_SECTION_HEADER * p_image_section_header = (IMAGE_SECTION_HEADER *)((ULONG)p_image_optional_header + p_image_file_header->SizeOfOptionalHeader);//必须加(ULONG),不然出错.

    for (int i = 0; i < p_image_file_header->NumberOfSections; i++) //规范规定是从1开始的.
    {
        if (rva >= p_image_section_header[i].VirtualAddress && rva <= (p_image_section_header[i].VirtualAddress + p_image_section_header[i].Misc.VirtualSize)) {
            offset = rva - p_image_section_header[i].VirtualAddress + p_image_section_header[i].PointerToRawData;
            break;
        }
    }

    UnmapViewOfFile(pmz);
    CloseHandle(hfilemap);
    CloseHandle(hfile);

    return offset;
}


bool on_import() //当点击导入表的时候的处理。
{
    //MessageBox(0,0,0,0);//ok成功.

    /*
    估计要用到的结构有:
    IMAGE_IMPORT_DESCRIPTOR
    IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA64
    IMAGE_IMPORT_BY_NAME
    #define IMAGE_ORDINAL_FLAG64 0x8000000000000000
    #define IMAGE_ORDINAL_FLAG32 0x80000000
    #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
    #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
    #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
    #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
    */

    bool r = false;//返回值.

    //先获取文件名.
    wchar_t wszfilename[_MAX_PATH] = {0};
    if (GetWindowText(g_h_edit_FilePath, wszfilename, _ARRAYSIZE(wszfilename)) == 0) {
        int x = GetLastError();
        return false;
    }

    HANDLE hfile = CreateFile(wszfilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD FileSizeHigh;
    DWORD FileSizeLow = GetFileSize(hfile, &FileSizeHigh);
    DWORD64 filesize = FileSizeHigh * 0x100000000 + FileSizeLow;

    if (FileSizeLow == 0 && FileSizeHigh == 0) {//如果文件大小为0.
        CloseHandle(hfile);
        return false;
    }

    HANDLE hfilemap = CreateFileMapping(hfile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* 空文件则返回失败 */
    if (hfilemap == NULL) {
        CloseHandle(hfile);
        return false;
    }

    LPVOID pmz = MapViewOfFile(hfilemap, SECTION_MAP_READ, NULL, NULL, 0/*映射所有*/);//暂时不支持大于4G的文件。
    if (pmz == NULL) {
        CloseHandle(hfilemap);
        CloseHandle(hfile);
        return false;
    }

    IMAGE_DOS_HEADER * p_image_dos_header = (IMAGE_DOS_HEADER *)pmz;
    if (IMAGE_DOS_SIGNATURE != p_image_dos_header->e_magic) {
        UnmapViewOfFile(pmz);
        CloseHandle(hfilemap);
        CloseHandle(hfile);
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
        UnmapViewOfFile(pmz);
        CloseHandle(hfilemap);
        CloseHandle(hfile);
        return false;
    }

    DWORD  CoffHeaderOffset = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew + sizeof(ULONG);
    IMAGE_FILE_HEADER * p_image_file_header = (IMAGE_FILE_HEADER *)CoffHeaderOffset;

    //注意这里用的永远是:IMAGE_OPTIONAL_HEADER32.
    //要分析IMAGE_OPTIONAL_HEADER64的一个办法是:强制定义一个,载赋值转换.
    //其实这个结构的大小是固定的,只不过32位的和64位的不一样.但还是用规范建议的.IMAGE_FILE_HEADER的成员访问好.
    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    //必须加(ULONG),不然出错.
    //IMAGE_SECTION_HEADER  * p_image_section_header = (IMAGE_SECTION_HEADER *)((ULONG)p_image_optional_header + p_image_file_header->SizeOfOptionalHeader);

    IMAGE_DATA_DIRECTORY * p_image_data_directory = 0;

    if (g_IsPE32Ex) {
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 112 + sizeof(IMAGE_DATA_DIRECTORY));//PE32+文件.
    } else {
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 96 + sizeof(IMAGE_DATA_DIRECTORY));
    }

    //先清空子节点.
    for (int i = 0; i < 260; i++) {        
        if (h_tree_import_dllname[i]) {//如果存在就清除.
            BOOL b = TreeView_DeleteItem(g_h_tree, h_tree_import_dllname[i]);
            if (!b) {
                int x = GetLastError();
                //return false;//其实这个失败无所谓,根本就不用检查.
            }
        }
    }

    BOOL bb = InvalidateRect(g_h_tree, 0, 0);//让改变立即显示.用上面的办法无效.

    /*
    得到地址，转换一下。
    得到IMAGE_IMPORT_DESCRIPTOR的地址，循环这个表，输出名字。
    注意：名字的偏移，不是第一个。
    */
    //PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)p_image_data_directory->VirtualAddress;

    //转换一下。
    PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)RVATOOFFSET(wszfilename, p_image_data_directory->VirtualAddress);

    DWORD p = (DWORD)piid;
    p += (DWORD)pmz;
    
    piid = (PIMAGE_IMPORT_DESCRIPTOR)p;//导入目录表的首地址。

    for (int i = 0; /*< (p_image_data_directory->VirtualAddress + p_image_data_directory->Size)*/; i++) {
        if (piid[i].Name == NULL) {//如果是最后一个就退出。
            break;
        }

        char * dllname = (char *)RVATOOFFSET(wszfilename, piid[i].Name);
        dllname += (DWORD)pmz;
        //MessageBoxA(0,dllname,0,0);

        //转换为宽字符,然后显示.
        wchar_t wszDllName[MAX_PATH] = {0};
        if (MultiByteToWideChar(CP_ACP, 0, (LPCSTR)dllname, lstrlenA((LPCSTR)dllname), wszDllName, _ARRAYSIZE(wszDllName)) == 0) {
            int x = GetLastError();
            break;
        }

        TV_INSERTSTRUCT tvinsert;
        tvinsert.hParent = g_htreeitem_data_directory[IMPORT];
        tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;//必须加这一行,不然不显示.
        tvinsert.item.pszText = wszDllName;
        h_tree_import_dllname[i] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
    }

    BOOL b = InvalidateRect(g_h_tree, 0, 0);//让改变立即显示.用上面的办法无效.

    UnmapViewOfFile(pmz);
    CloseHandle(hfilemap);
    CloseHandle(hfile);

    return r;//返回值暂时没有意义.
}