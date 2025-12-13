#include "pe32+.h"
#include "pe.h"
#include "section.h"
#include "Export.h"
#include "import.h"
#include "resource.h"

//#pragma comment(linker, "/ENTRY:Entry") 
//#pragma comment(linker, "/subsystem:windows")

wchar_t * g_tree_name[] = { //PE�ļ���˳��.ע�����Ҫ��,��ö��PE_Sһ��.
    L"DOSͷ",
    L"PE�ļ�ǩ��",
    L"COFF�ļ�ͷ",
    L"��ѡͷ",
    L"��׼��",
    L"�ض���",
    L"����Ŀ¼", //������������ӽڵ�.���ע��˵��������.
    L"����Ϣ",
    L"������",
    L"֤������",
    L"������Ϣ",
    L"��ϸ��Ϣ",
    L"˵��"
};

wchar_t * g_table_name[] = {//����Ŀ¼�Ķ�Ӧ������,ע�����Ҫ��
    L"������",
    L"�����",
    L"��Դ��",
    L"�쳣��",
    L"����֤���",
    L"��ַ�ض�λ��",
    L"��������",
    L"��ϵ�ܹ�",//����Ϊ���!Architecture
    L"ȫ��ָ��",
    L"�ֲ߳̾��洢(TLS)",
    L"�������ñ�",
    L"�󶨵����",
    L"�����ַ��",
    L"�ӳٵ���������",
    L"CLR����������",
    L"0" //��ӵ����������Ϊ�հ�!,��ʵ����ò���.
};

HWND hwndMain;//������.
HWND g_h_edit_FilePath;//��ʾ�ļ�·���õ�.
HWND g_h_static_prompt;//��ʾ��ק�ǲ���һ���Ϸ���PE�ļ��õ�.
HWND g_h_tree;//Ψһ��һ�����οؼ��ľ��.
HWND g_h_edit_rva;//RVA�����Ĵ��ھ��.
HWND g_h_edit_offset;//RVA�����Ĵ��ھ��.
HWND g_h[EXPLAIN + 1];//�Ѿ�ȷ�������οؼ��Ķ�Ӧ����ʾ�ؼ��ľ��.

HTREEITEM g_htreeitem[EXPLAIN + 1];//�洢���οؼ�����֪�������ı���.
HTREEITEM g_htreeitem_section[MAX_SECTION];//Ԥ�ȷ�����ô��,ʵ�ʵĲ��ᳬ�������.
HTREEITEM g_htreeitem_data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//Ԥ�ȷ�����ô��,ʵ�ʵĲ��ᳬ�������.

bool g_IsValidPE;//��һ����Ч��PE�ļ���?
bool g_IsPE32Ex;//��һ��PE32+�ļ���?

// Performance optimization: Helper structure to hold file mapping information
struct FileMappingInfo {
    HANDLE hfile;
    HANDLE hfilemap;
    LPVOID pmz;
    DWORD64 filesize;
    
    FileMappingInfo() : hfile(INVALID_HANDLE_VALUE), hfilemap(NULL), pmz(NULL), filesize(0) {}
    
    ~FileMappingInfo() {
        Cleanup();
    }
    
    void Cleanup() {
        if (pmz) {
            UnmapViewOfFile(pmz);
            pmz = NULL;
        }
        if (hfilemap) {
            CloseHandle(hfilemap);
            hfilemap = NULL;
        }
        if (hfile != INVALID_HANDLE_VALUE) {
            CloseHandle(hfile);
            hfile = INVALID_HANDLE_VALUE;
        }
    }
};

// Performance optimization: Map file once and reuse mapping
bool MapFileForReading(wchar_t * filename, FileMappingInfo & info) {
    info.hfile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (info.hfile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD FileSizeHigh;
    DWORD FileSizeLow = GetFileSize(info.hfile, &FileSizeHigh);
    info.filesize = ((DWORD64)FileSizeHigh << 32) | FileSizeLow;

    if (info.filesize == 0) {
        return false;
    }

    info.hfilemap = CreateFileMapping(info.hfile, NULL, PAGE_READONLY, NULL, NULL, NULL);
    if (info.hfilemap == NULL) {
        return false;
    }

    info.pmz = MapViewOfFile(info.hfilemap, SECTION_MAP_READ, NULL, NULL, 0);
    if (info.pmz == NULL) {
        return false;
    }

    return true;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//���뿪ʼ.


void ErrorBox(LPTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    DWORD dw = GetLastError();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

    // Display the error message and exit the process
    LPVOID lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf), TEXT("%s failed with error %d: %s"), lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


void on_create(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    /*
    ����ؼ���ʾ����󳤶�������.
    ���Բ�����ȡ����ؼ�������,Ӧ�ðѻ�ȡ������ק��·�����浽һ��ȫ�ֵı�������.
    ���߸ı�Ϊ����д�ı༭�ؼ�. | ES_READONLY
    */
    /*g_h_edit_FilePath = CreateWindowEx(WS_EX_CLIENTEDGE,L"Static",0,WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP, 0,0,800,21,hWnd,0,GetModuleHandle(0),0);*/
        //SendMessage(h_Static,WM_SETTEXT,0,(LPARAM)L"");
    g_h_edit_FilePath = CreateWindowEx(0, L"EDIT", 0, WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL, 0, 0, 800, 21, hWnd, 0, GetModuleHandle(0), 0);
    //SendMessage(g_h_edit_FilePath,WM_SETTEXT,0,(LPARAM)L"test");

    g_h_static_prompt = CreateWindowEx(WS_EX_CLIENTEDGE, L"Static", 0, WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP,
        800, 0, 199 - 6, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)L"����קһ��PE�ļ�����!");

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //�����Ƕ�̬����ʾ,�������Ϊ�ֲ�����.
    HWND h_Static_rva = CreateWindowEx(WS_EX_CLIENTEDGE, L"Static", 0, WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP, 0, 21, 40, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(h_Static_rva, WM_SETTEXT, 0, (LPARAM)L"RVA:");//(��������ַ�������ַ��ƫ��)

    g_h_edit_rva = CreateWindowEx(0, L"EDIT", 0, WS_CHILD | WS_VISIBLE, 40, 21, 140, 21, hWnd, 0, GetModuleHandle(0), 0);//ES_NUMBER ES_PASSWORD
    //SendMessage(h_sql,WM_SETTEXT,0,(LPARAM)L"������ʮ�����Ƶ���.");//(��������ַ�������ַ��ƫ��) ����Ҫ��0x ,��Ҫ��ǰ��׺   
    SendMessage(g_h_edit_rva, EM_SETLIMITTEXT, 16, 0);//�������16���ַ���ֻ��EDIT�ؼ���Ч.
    //HDC hdc = GetDC(g_h_edit_rva );
    //SetBkColor( hdc, 9999 );

    //�����Ƕ�̬����ʾ,�������Ϊ�ֲ�����.
    HWND h_static_offset = CreateWindowEx(WS_EX_CLIENTEDGE, L"Static", 0, WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP, 
        40 + 140, 21, 70, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(h_static_offset, WM_SETTEXT, 0, (LPARAM)L"OFFSET:");

    HWND g_h_edit_offset = CreateWindowEx(0, L"EDIT", 0, WS_CHILD | WS_VISIBLE, 40 + 140 + 70, 21, 140, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(g_h_edit_offset, EM_SETLIMITTEXT, 16, 0);//�������16���ַ���

    CreateWindowEx(NULL, L"button", L"ת��", WS_CHILD | WS_VISIBLE, 30 + 150 + 70 + 140, 21, 50, 21, hWnd, (HMENU)99, GetModuleHandle(0), NULL);
    CreateWindowEx(NULL, L"button", L"��ת", WS_CHILD | WS_VISIBLE, 30 + 150 + 70 + 140 + 9 + 50, 21, 50, 21, hWnd, (HMENU)100, GetModuleHandle(0), NULL);

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    InitCommonControls();
    g_h_tree = CreateWindowEx(0, L"SysTreeView32", 0,
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | WS_BORDER /*���߿�*/,
        0, 42, 170, 768 - 29 /*����ĸ߶�*/ - 21 - 21 - 102, hWnd, 0, GetModuleHandle(0), 0);

    TV_INSERTSTRUCT tvinsert;//һ��Tree�ؼ���ֻ���˴���һ��root�������Ϣѭ������Ϣ�Ĵ������е��鷳��

    tvinsert.hParent = 0;
    tvinsert.hInsertAfter = TVI_ROOT;
    tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;
    tvinsert.item.pszText = g_tree_name[DOS];//L"DOSͷ";//΢���Ĺ淶����ì��,һ��˵dosͷ����peͷ,һ���ַֿ���˵,�����Լ���ΪӦ�÷ֿ�,������������,�������Ҫ��.
    g_htreeitem[DOS] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    //tvinsert.hParent = 0;
    //tvinsert.item.pszText = L"PE�ļ�ͷ";
    //HTREEITEM pe_head = (HTREEITEM)SendMessage(h_network_tree,TVM_INSERTITEM,0,(LPARAM)& tvinsert);

    //��ʵ��i++Ҳ����,ֻ��������ķ�ʽ�������׶�.

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[PESIGN];//L"PE�ļ�ǩ��";
    g_htreeitem[PESIGN] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[COFF];//L"COFF�ļ�ͷ";
    g_htreeitem[COFF] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[MY_OPTIONAL];//L"��ѡͷ";
    g_htreeitem[MY_OPTIONAL] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = g_htreeitem[MY_OPTIONAL];
    tvinsert.item.pszText = g_tree_name[STANDARD];//L"��׼��";
    g_htreeitem[STANDARD] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    //tvinsert.hParent = h_OptionalHeader;
    //tvinsert.item.pszText = L"BaseOfData";//���Ӧ���ڱ�׼��.pe32+û�����.
    //HTREEITEM h_BaseOfData = (HTREEITEM)SendMessage(h_network_tree,TVM_INSERTITEM,0,(LPARAM)& tvinsert);            

    tvinsert.hParent = g_htreeitem[MY_OPTIONAL];
    tvinsert.item.pszText = g_tree_name[SPECIFIC];//L"�ض���";
    g_htreeitem[SPECIFIC] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = g_htreeitem[MY_OPTIONAL];
    tvinsert.item.pszText = g_tree_name[DATADIRECTORIES];//L"����Ŀ¼";
    g_htreeitem[DATADIRECTORIES] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[SECTIONTABLE];//L"����Ϣ";//��ʱ�������Ҳ����Ϣ,��֪����ɶ��Ϣ,������֤�����Ժ͵�����Ϣ.
    g_htreeitem[SECTIONTABLE] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[SECTIONDATA];//L"������";
    g_htreeitem[SECTIONDATA] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[CERTIFICATEATTRIBUTE];//L"֤������";//�淶˵�����ڽڵĺ����.
    g_htreeitem[CERTIFICATEATTRIBUTE] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[DEBUGINFORMATION];//L"������Ϣ";//�淶˵�����ڽڵĺ����.
    g_htreeitem[DEBUGINFORMATION] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[MOREINFORMATION];//L"���ֱ�";
    g_htreeitem[MOREINFORMATION] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[EXPLAIN];//L"˵��";
    g_htreeitem[EXPLAIN] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
}


// Performance optimization: Fixed resource leaks and improved error handling
int IsValidPE(wchar_t * filename)
{
    FileMappingInfo info;
    
    if (!MapFileForReading(filename, info)) {
        if (info.hfile == INVALID_HANDLE_VALUE) {
            int x = GetLastError();
            ErrorBox(TEXT("CreateFile"));
            return x;
        }
        return false;
    }

    IMAGE_DOS_HEADER * p_image_dos_header = (IMAGE_DOS_HEADER *)info.pmz;
    if (IMAGE_DOS_SIGNATURE != p_image_dos_header->e_magic) {
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    unsigned short int other = *(unsigned short int *)ntSignature;
    ntSignature = *(ULONG *)ntSignature;

    if (IMAGE_OS2_SIGNATURE == other) {
        MessageBox(0, filename, L"��ϲ��:����һ��NE�ļ�!", 0);
    }

    if (IMAGE_OS2_SIGNATURE_LE == other) {
        MessageBox(0, filename, L"��ϲ��:����һ��LE�ļ�!", 0);
    }

    if (IMAGE_NT_SIGNATURE == ntSignature) {
        return true;
    }

    return false;
}


// Performance optimization: Fixed resource leaks and improved error handling
bool IsPE32Ex(wchar_t * filename)
{
    FileMappingInfo info;
    
    if (!MapFileForReading(filename, info)) {
        return false;
    }

    IMAGE_DOS_HEADER * p_image_dos_header = (IMAGE_DOS_HEADER *)info.pmz;
    if (IMAGE_DOS_SIGNATURE != p_image_dos_header->e_magic) {
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
        return false;
    }

    DWORD  CoffHeaderOffset = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew + sizeof(ULONG);
    IMAGE_FILE_HEADER * p_image_file_header = (IMAGE_FILE_HEADER *)CoffHeaderOffset;

    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    if (p_image_optional_header->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return false;
    } else if (p_image_optional_header->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return true;
    } else if (p_image_optional_header->Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
        MessageBox(0, L"����һ��ROMӳ��", L"��ϲ!", 0);
    } else {
        MessageBox(0, L"����һ��δ֪�����͵�PE�ļ�!", L"��ϲ!", 0);
    }

    return false;
}


// Performance optimization: Fixed resource leaks and reduced duplicate code
bool AddSectionData(wchar_t * filename)
{
    FileMappingInfo info;
    
    if (!MapFileForReading(filename, info)) {
        return false;
    }

    IMAGE_DOS_HEADER * p_image_dos_header = (IMAGE_DOS_HEADER *)info.pmz;
    if (IMAGE_DOS_SIGNATURE != p_image_dos_header->e_magic) {
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
        return false;
    }

    DWORD  CoffHeaderOffset = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew + sizeof(ULONG);
    IMAGE_FILE_HEADER * p_image_file_header = (IMAGE_FILE_HEADER *)CoffHeaderOffset;

    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    IMAGE_SECTION_HEADER * p_image_section_header = (IMAGE_SECTION_HEADER *)((ULONG)p_image_optional_header + p_image_file_header->SizeOfOptionalHeader);

    // Performance optimization: Only clear items up to actual section count, not MAX_SECTION
    WORD numSections = min(p_image_file_header->NumberOfSections, MAX_SECTION);
    for (int i = 0; i < numSections; i++) {
        if (g_htreeitem_section[i]) {
            TreeView_DeleteItem(g_h_tree, g_htreeitem_section[i]);
            g_htreeitem_section[i] = NULL;
        }
    }

    for (int i = 0; i < numSections; i++) {
        wchar_t wszSectionName[9] = {0};
        // Performance optimization: Check string length before conversion
        int nameLen = strnlen((LPCSTR)p_image_section_header[i].Name, 8);
        if (nameLen > 0) {
            if (MultiByteToWideChar(CP_ACP, 0, (LPCSTR)p_image_section_header[i].Name, nameLen, wszSectionName, _ARRAYSIZE(wszSectionName)) == 0) {
                break;
            }

            TV_INSERTSTRUCT tvinsert;
            tvinsert.hParent = g_htreeitem[SECTIONDATA];
            tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;
            tvinsert.item.pszText = wszSectionName;
            g_htreeitem_section[i] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
        }
    }

    InvalidateRect(g_h_tree, 0, 0);
    return true;
}


// Performance optimization: Fixed resource leaks and reduced duplicate code  
bool AddMoreInformation(wchar_t * filename)
/*
��������ĳ�����νڵ����������ӽڵ�.�ӽڵ���Ǹ��ֱ�.������Ŀ¼ָ���.
*/
{
    FileMappingInfo info;
    
    if (!MapFileForReading(filename, info)) {
        return false;
    }

    IMAGE_DOS_HEADER * p_image_dos_header = (IMAGE_DOS_HEADER *)info.pmz;
    if (IMAGE_DOS_SIGNATURE != p_image_dos_header->e_magic) {
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
        return false;
    }

    DWORD  CoffHeaderOffset = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew + sizeof(ULONG);
    IMAGE_FILE_HEADER * p_image_file_header = (IMAGE_FILE_HEADER *)CoffHeaderOffset;

    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    IMAGE_DATA_DIRECTORY * p_image_data_directory = 0;

    if (g_IsPE32Ex) {
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 112);
    } else {
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 96);
    }

    // Performance optimization: Clear only existing items
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        if (g_htreeitem_data_directory[i]) {
            TreeView_DeleteItem(g_h_tree, g_htreeitem_data_directory[i]);
            g_htreeitem_data_directory[i] = NULL;
        }
    }

    // Performance optimization: Add only valid entries
    for (int m = 0; m < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; m++) {
        if (p_image_data_directory[m].VirtualAddress && p_image_data_directory[m].Size) {
            TV_INSERTSTRUCT tvinsert;
            tvinsert.hParent = g_htreeitem[MOREINFORMATION];
            tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;
            tvinsert.item.pszText = g_table_name[m];
            g_htreeitem_data_directory[m] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
        }
    }

    InvalidateRect(g_h_tree, 0, 0);
    return true;
}




void On_DropFiles(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    wchar_t szFileName[MAX_PATH] = {0};
    DragQueryFile((HDROP)wParam, 0, szFileName, _ARRAYSIZE(szFileName)); //ֻȡһ���ļ����ڶ���������������Ϊ0��KmdManager.exe ��������ʵ�ֵġ�

    //UINT cFiles = DragQueryFile((HDROP)wParam, (UINT)-1, NULL, 0);//�������û����.

    BOOL b = PathIsDirectory(szFileName);
    //if (b == true) //00B4161A  cmp         dword ptr [ebp-268h],1
    //if (b == TRUE) //00B4161A  cmp         dword ptr [ebp-268h],1
    if (b) //cmp         dword ptr [ebp-268h],0  
    {
        g_IsValidPE = false;
        g_IsPE32Ex = false;

        SendMessage(g_h_edit_FilePath, WM_SETTEXT, 0, 0);
        SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)L"����קһ��PE�ļ�����!");

        //�ļ���:C:\Users\Administrator\Desktop\aasdasf,�����ļ���С�Ƿ�Ϊ0.����ֵ��0.
        MessageBox(0, szFileName, L"����һ��Ŀ¼!,��ѡ��һ���ļ�", 0);
        //wchar_t buffer[MAX_PATH] = L"����һ��Ŀ¼,��ѡ��һ���ļ�.";
        //SendMessage(g_h_edit_FilePath,WM_SETTEXT,0,(LPARAM)buffer); 
    } else {
        int r = IsValidPE(szFileName);

        if (r == 1) {
            g_IsValidPE = true;

            SendMessage(g_h_edit_FilePath, WM_SETTEXT, 0, (LPARAM)szFileName);

            bool b = IsPE32Ex(szFileName);
            if (b) {
                g_IsPE32Ex = true;

                wchar_t buffer[MAX_PATH] = L"����һ��pe32+�ļ�.";
                SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)buffer);
            } else {
                wchar_t buffer[MAX_PATH] = L"����һ��pe32�ļ�.";
                SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)buffer);

                g_IsPE32Ex = false;
            }
        } else {
            g_IsValidPE = false;
            g_IsPE32Ex = false;

            SendMessage(g_h_edit_FilePath, WM_SETTEXT, 0, (LPARAM)0);
            wchar_t buffer[MAX_PATH] = L"����קһ��PE�ļ�����!";
            SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)buffer);

            if (r == 0) {
                MessageBox(0, szFileName, L"�ⲻ��һ����Ч��PE�ļ�.", 0);
            } else {
                //���Կ��ǵ�������Ϣ��
            }

            /*wchar_t buffer[MAX_PATH] = L"�ⲻ��һ��pe�ļ�.";
            SendMessage(g_h_static_prompt,WM_SETTEXT,0,(LPARAM)buffer);*/
        }

        //���ӽ������µ��ӽڵ�.
        bool b = AddSectionData(szFileName);

        //���ӱ��µ��ӽڵ�.
        b = AddMoreInformation(szFileName);// MOREINFORMATION
    }

    b = InvalidateRect(g_h_tree, 0, 0);//�øı�������ʾ.

    b = TreeView_Expand(g_h_tree, g_htreeitem[MOREINFORMATION], TVE_COLLAPSE);//�۵�
    //b = TreeView_Expand(g_h_tree, g_htreeitem_data_directory[IMPORT], TVE_EXPAND);

    DragFinish((HDROP)wParam);
}


void On_Notify_Click(HWND hWnd, WPARAM wParam, LPARAM lParam) //�ؼ��ĵ�������.
{
    //MessageBox(0,L"��굥��",L"���οؼ���Ϣ",0);

    //HTREEITEM hTreeItem = TreeView_GetSelection(g_h_tree);//�������û��!
    //if (hTreeItem)
    //{
    //    //MessageBox(0,0,0,0);
    //    //TreeView_DeleteItem(hwndTreeView, hTreeItem);
    //}

    //hTreeItem = TreeView_GetSelection(((LPNMHDR)lParam)->hwndFrom);//����������.
    //if (hTreeItem)
    //{
    //    MessageBox(0,0,0,0);
    //}

    //����һ:
    //TVHITTESTINFO hti;
    //POINT p1;
    //wchar_t achBuf[100] = {0};

    //GetCursorPos(&p1);
    //hti.flags=TVHT_ONITEM;
    //memcpy(&hti.pt, &p1, sizeof(POINT));
    //ScreenToClient(((LPNMHDR)lParam)->hwndFrom, &hti.pt);

    //TVITEM tv;
    //ZeroMemory(&tv, sizeof(TVITEM));
    //tv.hItem=(HTREEITEM)TreeView_HitTest(((LPNMHDR)lParam)->hwndFrom, &hti);
    //tv.cchTextMax=100;
    //tv.pszText=achBuf;
    //tv.mask=TVIF_TEXT|TVIF_HANDLE;
    //TreeView_GetItem(((LPNMHDR)lParam)->hwndFrom,&tv);

    //MessageBox(0,tv.pszText,0,0);

    //////////////////////////////////////////////////////////////////////////
    //������:��ʵ��һ����.

    if (((LPNMHDR)lParam)->hwndFrom == g_h_tree) //��������οؼ�,���п������б��ؼ�.
    {
        LPNMHDR lpnmh = (LPNMHDR)lParam;
        DWORD dwPos = GetMessagePos();

        POINT pt;
        pt.x = LOWORD(dwPos);
        pt.y = HIWORD(dwPos);
        ScreenToClient(lpnmh->hwndFrom, &pt);

        TVHITTESTINFO ht = {0};
        ht.pt = pt;
        ht.flags = TVHT_ONITEM;
        HTREEITEM hItem = TreeView_HitTest(lpnmh->hwndFrom, &ht);

        TVITEM ti = {0};
        ti.mask = TVIF_HANDLE | TVIF_TEXT;
        TCHAR buf[MAX_PATH] = {0};
        ti.cchTextMax = _ARRAYSIZE(buf);
        ti.pszText = buf;
        ti.hItem = hItem;
        TreeView_GetItem(lpnmh->hwndFrom, &ti);

        /*
        ��ʵ��Ҳ����һ���������:��ȡ�ռ���ַ�,���ļ�·��,Ȼ��У������ļ��Ƿ�Ϸ�.
        �Ӻ���һ��������:�����հ״�,��������ʾ.
        */
        if (g_IsValidPE == false && lstrlen(buf) != 0) {
            MessageBox(0, L"��ѡ��һ����Ч��PE�ļ�", L"�Ѻ���ʾ!", 0);
            return;
        }

        //1.�����ԭ����֪�����οؼ��Ľڵ㼰�ӽڵ�
        //�Ƚ�ÿ���ڵ�,��ĳ���ڵ�,��ѡ����Ӧ�Ľڵ㴦������.

        //2.����ǽ����ݵ��ӽڵ�.
        //�Ƚ�ÿ���ڵ�,��ĳ���ڵ�,��ѡ����Ӧ�Ľڵ㴦������.
        //����ڵ������û�б���,���Ը�������������һ��,Ȼ���ٶ�λ.

        //3.�������ϸ��Ϣ���ӽڵ�.
        //�Ƚ�ÿ���ڵ�,��ĳ���ڵ�,��ѡ����Ӧ�Ľڵ㴦������.

        //���������Ŀ¼����ϸ��Ϣ��
        if (lstrcmpi(buf, g_tree_name[MOREINFORMATION]) == 0) {
            on_import();

            //���滹�����и���Ĵ�����

            BOOL b = InvalidateRect(g_h_tree, 0, 0);//�øı�������ʾ.������İ취��Ч.
        }


        //����ǲ�������Ŀ¼���ӽڵ㡣
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            //wchar_t wszName[9] = {0};
            //if (MultiByteToWideChar(CP_ACP, 0,(LPCSTR)buf,lstrlenA((LPCSTR)buf),wszName,sizeof(wszName)) == 0) 
            //{
            //    int x = GetLastError();
            //    //r = false;
            //    break;
            //    //return FALSE;
            //}

            if (lstrcmpi(buf, g_table_name[i]) == 0) {
                switch (i) {
                case EXPORT://��ʵ���Ҳ���Ը��ö��,
                    //On_Export(hWnd, wParam, lParam);//���Ҳ���Ը����������,��Ӧ�����ö��.
                    break;
                case IMPORT: //��ʵҲ���������:IMAGE_DIRECTORY_ENTRY_IMPORTϵͳ�Զ����..
                    //on_import();                         
                    break;
                case RESOURCE:

                    break;
                case EXCEPTION:

                    break;
                case CERTIFICATE:

                    break;
                case BASE_RELOCATION:

                    break;
                case DEBUG:

                    break;
                case ARCHITECTURE:

                case CLOBAL_PTR:

                    break;
                case TLS:

                case LOAD_CONFIG:

                    break;
                case BOUND_INPORT:

                    break;
                case IAT:

                    break;
                case DELAY_INPORT_DESCRIPTOR:

                    break;
                case CLR_RUNTIME_HEADER:

                    break;
                default:
                    return;
                }
                break;//������п���.
            }//end if
        }//end for




    }//end if
}


void On_Notify_SelChanged(HWND hWnd, WPARAM wParam, LPARAM lParam)
/*
�ؼ���ѡ��ı仯�Ĵ���.
�����ʱ����.
*/
{
    //MessageBox(0,L"ѡ��ı�",L"���οؼ���Ϣ",0);

    HTREEITEM hTreeItem = TreeView_GetSelection(g_h_tree);
    if (hTreeItem) {
        //MessageBox(0,0,0,0);//���Ҳ������.
    }

    //hTreeItem = TreeView_GetSelection(((LPNMHDR)lParam)->hwndFrom);
    if (hTreeItem) {
        //MessageBox(0,0,0,0);//���Ҳ������.
    }

    TVITEM tvi;
    TCHAR szText[MAX_PATH] = {0};
    memset(&tvi, 0, sizeof(tvi));
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hTreeItem;//g_h_tree;//the item handle;
    tvi.pszText = szText;
    tvi.cchTextMax = sizeof(szText);
    BOOL bSuccess = TreeView_GetItem(((LPNMHDR)lParam)->hwndFrom, &tvi);

    //MessageBox(0,tvi.pszText,0,0);//����취����ȷ��.
}


void On_Notify(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    switch (((LPNMHDR)lParam)->code) {
    case NM_CLICK://�������.���泣�иı����Ϣ.
        On_Notify_Click(hWnd, wParam, lParam);
        break;
        //case NM_DBLCLK://���˫����.ǰ�泣�е�������Ϣ.
        //    MessageBox(0,L"���˫��",L"���οؼ���Ϣ",0);
        //    break; 
        //case TVN_KEYDOWN ://�������.
        //    MessageBox(0,L"���̰���",L"���οؼ���Ϣ",0);
        //    break; 
    case TVN_SELCHANGED://ѡ��ı�
    { //�����������,�������������,Ҳ���Կ���������ı���.
        On_Notify_SelChanged(hWnd, wParam, lParam);
    }
    break;
    }
}


LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_CREATE:
        on_create(hWnd, wParam, lParam);
        break;
    case WM_LBUTTONDOWN:
        SendMessage(hWnd, WM_SYSCOMMAND, SC_MOVE | HTCAPTION, 0);//֧���϶�������SendMessage,hWnd,WM_NCLBUTTONDOWN,HTCAPTION,lParam        
        break;
    case WM_DROPFILES:
        On_DropFiles(hWnd, wParam, lParam);
        break;
    case WM_NOTIFY:
        On_Notify(hWnd, wParam, lParam);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return(DefWindowProc(hWnd, uMsg, wParam, lParam));
    }
    return(0);
}


bool get_r(RECTANGLE & r)
{
    r.w = 999;
    r.h = 768 - 102;

    int hc = GetSystemMetrics(SM_CYCAPTION);//�����ؼ������ͨ���ڱ���ĸ߶�:19

    int xs = GetSystemMetrics(SM_CXSCREEN);
    int ys = GetSystemMetrics(SM_CYSCREEN);
    r.x = (xs - r.w) / 2;
    r.y = (ys - r.h /*�����ȫ������,���Կ��Ǽ�ȥ�������ĸ߶�*/) / 2;//������ʾ�����x,yΪ��������x,y������Ϊ0.

    if (xs < 999 || ys < 768) {
        MessageBox(0, L"�����Ļ�ķֱ��ʹ�С,��С����Ϊ:1024X768.�����ú��������г���.", L"������ʾ", 0);
        ExitProcess(0);
        r.x = r.y = 0;
    }

    return true;
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
//void Entry() 
{
    RECTANGLE r = {0};
    get_r(r);

    WNDCLASSEX sWndClassEx = {48,3,WindowProc,0,0,GetModuleHandle(0),0,LoadCursor(0,IDC_ARROW),(HBRUSH)COLOR_BACKGROUND /*6*/,0,L"correy",0};
    ATOM a = RegisterClassEx(&sWndClassEx);
    hwndMain = CreateWindowEx(WS_EX_ACCEPTFILES, L"correy", L"pe32+", 0x0Ca0000, r.x, r.y, r.w, r.h, 0, 0, GetModuleHandle(0), 0);
    ShowWindow(hwndMain, 1);
    UpdateWindow(hwndMain);//��ü���.

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {   //���ﻹ���Լ����ݼ���TranslateAccelerator��
        if (!TranslateAccelerator(msg.hwnd, 0, &msg)) //hAccelTable ֧�ֿ�ݼ��Ͳ˵���
        {
            TranslateMessage(&msg);//֧������İ������ַ���
            DispatchMessage(&msg);
        }
    }

    ExitProcess(0);
}