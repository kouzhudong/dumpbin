#include "import.h"
#include "pe32+.h"

extern bool g_IsPE32Ex;//��һ��PE32+�ļ���?
extern HTREEITEM g_htreeitem_data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//Ԥ�ȷ�����ô��,ʵ�ʵĲ��ᳬ�������
extern HWND g_h_tree;//Ψһ��һ�����οؼ��ľ��.
extern HTREEITEM g_htreeitem[EXPLAIN + 1];//�洢���οؼ�����֪�������ı���.
extern wchar_t * g_table_name[];
extern HWND g_h_edit_FilePath;//��ʾ�ļ�·���õ�.

//������DLL���ֵ����οؼ��ľ������ʱ�������Ϊ������.
HTREEITEM h_tree_import_dllname[260] = {0};

unsigned int RVATOOFFSET(IN wchar_t * filename, IN unsigned int rva)
/*
���أ���ʾʧ�ܣ������������ļ��е�ƫ�ơ�
*/
{
    unsigned int offset = 0;//����ֵ��

    HANDLE hfile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD FileSizeHigh;
    DWORD FileSizeLow = GetFileSize(hfile, &FileSizeHigh);
    DWORD64 filesize = FileSizeHigh * 0x100000000 + FileSizeLow;

    if (FileSizeLow == 0 && FileSizeHigh == 0) {//����ļ���СΪ0.
        CloseHandle(hfile);
        return false;
    }

    HANDLE hfilemap = CreateFileMapping(hfile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* ���ļ��򷵻�ʧ�� */
    if (hfilemap == NULL) {
        CloseHandle(hfile);
        return false;
    }

    LPVOID pmz = MapViewOfFile(hfilemap, SECTION_MAP_READ, NULL, NULL, 0/*ӳ������*/);//��ʱ��֧�ִ���4G���ļ���
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

    //ע�������õ���Զ��:IMAGE_OPTIONAL_HEADER32.
    //Ҫ����IMAGE_OPTIONAL_HEADER64��һ���취��:ǿ�ƶ���һ��,�ظ�ֵת��.
    //��ʵ����ṹ�Ĵ�С�ǹ̶���,ֻ����32λ�ĺ�64λ�Ĳ�һ��.�������ù淶�����.IMAGE_FILE_HEADER�ĳ�Ա���ʺ�.
    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    IMAGE_SECTION_HEADER * p_image_section_header = (IMAGE_SECTION_HEADER *)((ULONG)p_image_optional_header + p_image_file_header->SizeOfOptionalHeader);//�����(ULONG),��Ȼ����.

    for (int i = 0; i < p_image_file_header->NumberOfSections; i++) //�淶�涨�Ǵ�1��ʼ��.
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


bool on_import() //�����������ʱ��Ĵ���
{
    //MessageBox(0,0,0,0);//ok�ɹ�.

    /*
    ����Ҫ�õ��Ľṹ��:
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

    bool r = false;//����ֵ.

    //�Ȼ�ȡ�ļ���.
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

    if (FileSizeLow == 0 && FileSizeHigh == 0) {//����ļ���СΪ0.
        CloseHandle(hfile);
        return false;
    }

    HANDLE hfilemap = CreateFileMapping(hfile, NULL, PAGE_READONLY, NULL, NULL, NULL); /* ���ļ��򷵻�ʧ�� */
    if (hfilemap == NULL) {
        CloseHandle(hfile);
        return false;
    }

    LPVOID pmz = MapViewOfFile(hfilemap, SECTION_MAP_READ, NULL, NULL, 0/*ӳ������*/);//��ʱ��֧�ִ���4G���ļ���
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

    //ע�������õ���Զ��:IMAGE_OPTIONAL_HEADER32.
    //Ҫ����IMAGE_OPTIONAL_HEADER64��һ���취��:ǿ�ƶ���һ��,�ظ�ֵת��.
    //��ʵ����ṹ�Ĵ�С�ǹ̶���,ֻ����32λ�ĺ�64λ�Ĳ�һ��.�������ù淶�����.IMAGE_FILE_HEADER�ĳ�Ա���ʺ�.
    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    //�����(ULONG),��Ȼ����.
    //IMAGE_SECTION_HEADER  * p_image_section_header = (IMAGE_SECTION_HEADER *)((ULONG)p_image_optional_header + p_image_file_header->SizeOfOptionalHeader);

    IMAGE_DATA_DIRECTORY * p_image_data_directory = 0;

    if (g_IsPE32Ex) {
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 112 + sizeof(IMAGE_DATA_DIRECTORY));//PE32+�ļ�.
    } else {
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 96 + sizeof(IMAGE_DATA_DIRECTORY));
    }

    //������ӽڵ�.
    for (int i = 0; i < 260; i++) {        
        if (h_tree_import_dllname[i]) {//������ھ����.
            BOOL b = TreeView_DeleteItem(g_h_tree, h_tree_import_dllname[i]);
            if (!b) {
                int x = GetLastError();
                //return false;//��ʵ���ʧ������ν,�����Ͳ��ü��.
            }
        }
    }

    BOOL bb = InvalidateRect(g_h_tree, 0, 0);//�øı�������ʾ.������İ취��Ч.

    /*
    �õ���ַ��ת��һ�¡�
    �õ�IMAGE_IMPORT_DESCRIPTOR�ĵ�ַ��ѭ�������������֡�
    ע�⣺���ֵ�ƫ�ƣ����ǵ�һ����
    */
    //PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)p_image_data_directory->VirtualAddress;

    //ת��һ�¡�
    PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)RVATOOFFSET(wszfilename, p_image_data_directory->VirtualAddress);

    DWORD p = (DWORD)piid;
    p += (DWORD)pmz;
    
    piid = (PIMAGE_IMPORT_DESCRIPTOR)p;//����Ŀ¼����׵�ַ��

    for (int i = 0; /*< (p_image_data_directory->VirtualAddress + p_image_data_directory->Size)*/; i++) {
        if (piid[i].Name == NULL) {//��������һ�����˳���
            break;
        }

        char * dllname = (char *)RVATOOFFSET(wszfilename, piid[i].Name);
        dllname += (DWORD)pmz;
        //MessageBoxA(0,dllname,0,0);

        //ת��Ϊ���ַ�,Ȼ����ʾ.
        wchar_t wszDllName[MAX_PATH] = {0};
        if (MultiByteToWideChar(CP_ACP, 0, (LPCSTR)dllname, lstrlenA((LPCSTR)dllname), wszDllName, _ARRAYSIZE(wszDllName)) == 0) {
            int x = GetLastError();
            break;
        }

        TV_INSERTSTRUCT tvinsert;
        tvinsert.hParent = g_htreeitem_data_directory[IMPORT];
        tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;//�������һ��,��Ȼ����ʾ.
        tvinsert.item.pszText = wszDllName;
        h_tree_import_dllname[i] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
    }

    BOOL b = InvalidateRect(g_h_tree, 0, 0);//�øı�������ʾ.������İ취��Ч.

    UnmapViewOfFile(pmz);
    CloseHandle(hfilemap);
    CloseHandle(hfile);

    return r;//����ֵ��ʱû������.
}