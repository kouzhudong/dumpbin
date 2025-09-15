#include "pe32+.h"
#include "pe.h"
#include "section.h"
#include "Export.h"
#include "import.h"
#include "resource.h"

//#pragma comment(linker, "/ENTRY:Entry") 
//#pragma comment(linker, "/subsystem:windows")

wchar_t * g_tree_name[] = { //PE文件的顺序.注意次序不要乱,这枚举PE_S一致.
    L"DOS头",
    L"PE文件签名",
    L"COFF文件头",
    L"可选头",
    L"标准域",
    L"特定域",
    L"数据目录", //这个不会再有子节点.这个注释说明很有用.
    L"节信息",
    L"节数据",
    L"证书属性",
    L"调试信息",
    L"详细信息",
    L"说明"
};

wchar_t * g_table_name[] = {//数据目录的对应的名字,注意次序不要乱
    L"导出表",
    L"导入表",
    L"资源表",
    L"异常表",
    L"属性证书表",
    L"基址重定位表",
    L"调试数据",
    L"体系架构",//设置为零吧!Architecture
    L"全局指针",
    L"线程局部存储(TLS)",
    L"加载配置表",
    L"绑定导入表",
    L"导入地址表",
    L"延迟导入描述符",
    L"CLR导入描述符",
    L"0" //多加的这个就设置为空吧!,其实这个用不到.
};

HWND hwndMain;//主窗口.
HWND g_h_edit_FilePath;//显示文件路径用的.
HWND g_h_static_prompt;//提示拖拽是不是一个合法的PE文件用的.
HWND g_h_tree;//唯一的一个树形控件的句柄.
HWND g_h_edit_rva;//RVA输入框的窗口句柄.
HWND g_h_edit_offset;//RVA输入框的窗口句柄.
HWND g_h[EXPLAIN + 1];//已经确定的树形控件的对应的显示控件的句柄.

HTREEITEM g_htreeitem[EXPLAIN + 1];//存储树形控件的已知的数量的变量.
HTREEITEM g_htreeitem_section[MAX_SECTION];//预先分配这么多,实际的不会超过这个数.
HTREEITEM g_htreeitem_data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//预先分配这么多,实际的不会超过这个数.

bool g_IsValidPE;//是一个有效的PE文件吗?
bool g_IsPE32Ex;//是一个PE32+文件吗?

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//代码开始.


void ErrorBox(LPTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

    // Display the error message and exit the process
    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf), TEXT("%s failed with error %d: %s"), lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    //ExitProcess(dw); 
}


void on_create(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    /*
    这个控件显示的最大长度有限制.
    所以不可以取这个控件的内容,应该把获取到的拖拽的路径保存到一个全局的变量里面.
    或者改变为不可写的编辑控件. | ES_READONLY
    */
    /*g_h_edit_FilePath = CreateWindowEx(WS_EX_CLIENTEDGE,L"Static",0,WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP,
        0,0,800,21,hWnd,0,GetModuleHandle(0),0);*/
        //SendMessage(h_Static,WM_SETTEXT,0,(LPARAM)L"");
    g_h_edit_FilePath = CreateWindowEx(0, L"EDIT", 0, WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
        0, 0, 800, 21, hWnd, 0, GetModuleHandle(0), 0);
    //SendMessage(g_h_edit_FilePath,WM_SETTEXT,0,(LPARAM)L"test");

    g_h_static_prompt = CreateWindowEx(WS_EX_CLIENTEDGE, L"Static", 0, WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP,
        800, 0, 199 - 6, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)L"请拖拽一个PE文件过来!");

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //不考虑动态的显示,这个可以为局部变量.
    HWND h_Static_rva = CreateWindowEx(WS_EX_CLIENTEDGE, L"Static", 0, WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP,
        0, 21, 40, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(h_Static_rva, WM_SETTEXT, 0, (LPARAM)L"RVA:");//(相对虚拟地址或虚拟地址的偏移)

    g_h_edit_rva = CreateWindowEx(0, L"EDIT", 0, WS_CHILD | WS_VISIBLE, 40, 21, 140, 21, hWnd, 0, GetModuleHandle(0), 0);//ES_NUMBER ES_PASSWORD
    //SendMessage(h_sql,WM_SETTEXT,0,(LPARAM)L"请输入十六进制的数.");//(相对虚拟地址或虚拟地址的偏移) 不需要加0x ,不要带前后缀   
    SendMessage(g_h_edit_rva, EM_SETLIMITTEXT, 16, 0);//最多输入16个字符。只对EDIT控件有效.
    //HDC hdc = GetDC(g_h_edit_rva );
    //SetBkColor( hdc, 9999 );

    //不考虑动态的显示,这个可以为局部变量.
    HWND h_static_offset = CreateWindowEx(WS_EX_CLIENTEDGE, L"Static", 0, WS_CHILD | WS_VISIBLE | SS_LEFT | WS_GROUP,
        40 + 140, 21, 70, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(h_static_offset, WM_SETTEXT, 0, (LPARAM)L"OFFSET:");

    HWND g_h_edit_offset = CreateWindowEx(0, L"EDIT", 0, WS_CHILD | WS_VISIBLE, 40 + 140 + 70, 21, 140, 21, hWnd, 0, GetModuleHandle(0), 0);
    SendMessage(g_h_edit_offset, EM_SETLIMITTEXT, 16, 0);//最多输入16个字符。

    CreateWindowEx(NULL, L"button", L"转换", WS_CHILD | WS_VISIBLE, 30 + 150 + 70 + 140, 21, 50, 21, hWnd, (HMENU)99, GetModuleHandle(0), NULL);
    CreateWindowEx(NULL, L"button", L"逆转", WS_CHILD | WS_VISIBLE, 30 + 150 + 70 + 140 + 9 + 50, 21, 50, 21, hWnd, (HMENU)100, GetModuleHandle(0), NULL);

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    InitCommonControls();
    g_h_tree = CreateWindowEx(0, L"SysTreeView32", 0,
        WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | WS_BORDER /*带边框*/,
        0, 42, 170, 768 - 29 /*标题的高度*/ - 21 - 21 - 102, hWnd, 0, GetModuleHandle(0), 0);

    TV_INSERTSTRUCT tvinsert;

    tvinsert.hParent = 0;
    tvinsert.hInsertAfter = TVI_ROOT;
    tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;
    tvinsert.item.pszText = g_tree_name[DOS];//L"DOS头";//微软的规范自相矛盾,一会说dos头属于pe头,一会又分开来说,所以自己认为应该分开,这样容易理解,这才是重要的.
    g_htreeitem[DOS] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    //tvinsert.hParent = 0;
    //tvinsert.item.pszText = L"PE文件头";
    //HTREEITEM pe_head = (HTREEITEM)SendMessage(h_network_tree,TVM_INSERTITEM,0,(LPARAM)& tvinsert);

    //其实用i++也可以,只不过下面的方式更明显易懂.

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[PESIGN];//L"PE文件签名";
    g_htreeitem[PESIGN] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[COFF];//L"COFF文件头";
    g_htreeitem[COFF] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[MY_OPTIONAL];//L"可选头";
    g_htreeitem[MY_OPTIONAL] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = g_htreeitem[MY_OPTIONAL];
    tvinsert.item.pszText = g_tree_name[STANDARD];//L"标准域";
    g_htreeitem[STANDARD] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    //tvinsert.hParent = h_OptionalHeader;
    //tvinsert.item.pszText = L"BaseOfData";//这个应属于标准域.pe32+没有这个.
    //HTREEITEM h_BaseOfData = (HTREEITEM)SendMessage(h_network_tree,TVM_INSERTITEM,0,(LPARAM)& tvinsert);            

    tvinsert.hParent = g_htreeitem[MY_OPTIONAL];
    tvinsert.item.pszText = g_tree_name[SPECIFIC];//L"特定域";
    g_htreeitem[SPECIFIC] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = g_htreeitem[MY_OPTIONAL];
    tvinsert.item.pszText = g_tree_name[DATADIRECTORIES];//L"数据目录";
    g_htreeitem[DATADIRECTORIES] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[SECTIONTABLE];//L"节信息";//有时候这后面也有信息,不知道是啥信息,怀疑是证书属性和调试信息.
    g_htreeitem[SECTIONTABLE] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[SECTIONDATA];//L"节数据";
    g_htreeitem[SECTIONDATA] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[CERTIFICATEATTRIBUTE];//L"证书属性";//规范说明是在节的后面的.
    g_htreeitem[CERTIFICATEATTRIBUTE] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[DEBUGINFORMATION];//L"调试信息";//规范说明是在节的后面的.
    g_htreeitem[DEBUGINFORMATION] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[MOREINFORMATION];//L"各种表";
    g_htreeitem[MOREINFORMATION] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

    tvinsert.hParent = 0;
    tvinsert.item.pszText = g_tree_name[EXPLAIN];//L"说明";
    g_htreeitem[EXPLAIN] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
}


int IsValidPE(wchar_t * filename)
{
    bool r = false;//返回值.

    HANDLE hfile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        int x = GetLastError();//0x00000020
        //MessageBox(0,L"请检查文件是否被占用或者访问权限等设置!",L"打开文件失败!",0);
        //可以考虑把文件名也显示出来。
        ErrorBox(TEXT("CreateFile"));
        return x;
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

    LPVOID pmz = MapViewOfFile(hfilemap, SECTION_MAP_READ, NULL, NULL, 0/*映射所有*/);//应该支持大于4G的文件。
    if (pmz == NULL) {
        CloseHandle(hfilemap);
        CloseHandle(hfile);
        return false;
    }

    IMAGE_DOS_HEADER * p_image_dos_header = (IMAGE_DOS_HEADER *)pmz;
    if (IMAGE_DOS_SIGNATURE != p_image_dos_header->e_magic) {
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    unsigned short int other = *(unsigned short int *)ntSignature;
    ntSignature = *(ULONG *)ntSignature;

    if (IMAGE_OS2_SIGNATURE == other) {
        MessageBox(0, filename, L"恭喜你:这是一个NE文件!", 0);
        //return false;//要运行下面的,要是放句柄.
    }

    if (IMAGE_OS2_SIGNATURE_LE == other) //IMAGE_VXD_SIGNATURE
    {
        MessageBox(0, filename, L"恭喜你:这是一个LE文件!", 0);
        //return false;
    }

    if (IMAGE_NT_SIGNATURE == ntSignature) {
        //return false;
        r = true;
    }

    UnmapViewOfFile(pmz);
    CloseHandle(hfilemap);
    CloseHandle(hfile);

    return r;
}


bool IsPE32Ex(wchar_t * filename)
{//其实这个函数的返回类型可以是int,分别代表不同的PE文件类型.

    //IMAGE_DOS_HEADER      image_dos_header;
    //IMAGE_FILE_HEADER     image_file_header;
    //IMAGE_OPTIONAL_HEADER image_optional_header;
    //IMAGE_SECTION_HEADER  image_section_header;
    //IMAGE_NT_HEADERS 微软的示例都不用这个,看来这个只是概念,别的无用.

    bool r = false;//返回值.

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
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
        return false;
    }

    DWORD  CoffHeaderOffset = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew + sizeof(ULONG);
    IMAGE_FILE_HEADER * p_image_file_header = (IMAGE_FILE_HEADER *)CoffHeaderOffset;

    //注意这里用的永远是:IMAGE_OPTIONAL_HEADER32.
    //要分析IMAGE_OPTIONAL_HEADER64的一个办法是:强制定义一个,载赋值转换.
    //其实这个结构的大小是固定的,只不过32位的和64位的不一样.但还是用规范建议的.IMAGE_FILE_HEADER的成员访问好.
    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    if (p_image_optional_header->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        //这是一个普通的PE文件
        //return false;//要运行下面的,要是放句柄.

    } else if (p_image_optional_header->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        //这是一个的PE32+文件
        //return true;
        r = true;
    } else if (p_image_optional_header->Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
        //这是一个的ROM映像
        MessageBox(0, L"这是一个ROM映像", L"惊喜!", 0);
    } else {
        //未知的文件类型.
        MessageBox(0, L"这是一个未知的类型的PE文件!", L"惊喜!", 0);
    }

    UnmapViewOfFile(pmz);
    CloseHandle(hfilemap);
    CloseHandle(hfile);

    return r;
}


bool AddSectionData(wchar_t * filename)
/*
功能是在节数据这个树形节点下面添加子节点.
*/
{
    //IMAGE_DOS_HEADER      image_dos_header;
    //IMAGE_FILE_HEADER     image_file_header;
    //IMAGE_OPTIONAL_HEADER image_optional_header;
    //IMAGE_SECTION_HEADER  image_section_header;
    //IMAGE_NT_HEADERS 微软的示例都不用这个,看来这个只是概念,别的无用.

    bool r = false;//返回值.

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
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
        return false;
    }

    DWORD  CoffHeaderOffset = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew + sizeof(ULONG);
    IMAGE_FILE_HEADER * p_image_file_header = (IMAGE_FILE_HEADER *)CoffHeaderOffset;

    //注意这里用的永远是:IMAGE_OPTIONAL_HEADER32.
    //要分析IMAGE_OPTIONAL_HEADER64的一个办法是:强制定义一个,载赋值转换.
    //其实这个结构的大小是固定的,只不过32位的和64位的不一样.但还是用规范建议的.IMAGE_FILE_HEADER的成员访问好.
    IMAGE_OPTIONAL_HEADER * p_image_optional_header = (IMAGE_OPTIONAL_HEADER *)((ULONG)p_image_file_header + sizeof(IMAGE_FILE_HEADER));

    IMAGE_SECTION_HEADER * p_image_section_header = (IMAGE_SECTION_HEADER *)((ULONG)p_image_optional_header + p_image_file_header->SizeOfOptionalHeader);//必须加(ULONG),不然出错.

    //先清空子节点.
    for (int i = 0; i < MAX_SECTION; i++) {
        //如果存在就清除.
        if (g_htreeitem_section[i]) {
            BOOL b = TreeView_DeleteItem(g_h_tree, g_htreeitem_section[i]);
            if (!b) {
                int x = GetLastError();
                //return false;//其实这个失败无所谓,根本就不用检查.
            }
        }
    }

    //BOOL b = InvalidateRect(g_h_tree,0,0);//让改变立即显示.用上面的办法无效.

    //for ( ;p_image_section_header =  ; p_image_section_header += IMAGE_SIZEOF_SECTION_HEADER) //这个办法太笨.
    for (int i = 0; i < p_image_file_header->NumberOfSections; i++) //规范规定是从1开始的.
    {
        //转换为宽字符,然后显示.
        wchar_t wszSectionName[9] = {0};
        if (MultiByteToWideChar(CP_ACP, 0, (LPCSTR)p_image_section_header[i].Name, lstrlenA((LPCSTR)p_image_section_header[i].Name), wszSectionName, sizeof(wszSectionName)) == 0) {
            int x = GetLastError();
            //r = false;
            break;
            //return FALSE;
        }

        TV_INSERTSTRUCT tvinsert;

        tvinsert.hParent = g_htreeitem[SECTIONDATA];
        tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;//必须加这一行,不然不显示.
        tvinsert.item.pszText = wszSectionName;
        g_htreeitem_section[i] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
    }

    BOOL b = InvalidateRect(g_h_tree, 0, 0);//让改变立即显示.用上面的办法无效.

    UnmapViewOfFile(pmz);
    CloseHandle(hfilemap);
    CloseHandle(hfile);

    return r;//返回值在那时没有意义.

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ////一下是测试代码:添加节点用的.
    //TV_INSERTSTRUCT tvinsert;

    //tvinsert.hParent = g_htreeitem[SECTIONDATA];
    ////tvinsert.hInsertAfter = g_htreeitem[SECTIONDATA];
    //tvinsert.item.mask = TVIF_TEXT+TVIF_IMAGE+TVIF_SELECTEDIMAGE;
    //tvinsert.item.pszText = L"test";//L"DOS头";
    //g_htreeitem_section[0]  = (HTREEITEM)SendMessage(g_h_tree,TVM_INSERTITEM,0,(LPARAM)& tvinsert);
    ////UpdateWindow(g_h_tree);
    ////UpdateWindow(hwndMain);

    //BOOL b = InvalidateRect(g_h_tree,0,0);//让改变立即显示.用上面的办法无效.

    ////另一个思路是:用下面的宏,没有实验.
    ////HTREEITEM TreeView_InsertItem(HWND hwndTV, LPTVINSERTSTRUCT lpis);
    ////////////////////////////////////////////////////////////////////////////////////////////////
}


bool AddMoreInformation(wchar_t * filename)
/*
功能是在某个树形节点下面添加子节点.子节点就是各种表.由数据目录指向的.
*/
{
    bool r = false;//返回值.

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
        return false;
    }

    ULONG  ntSignature = (ULONG)p_image_dos_header + p_image_dos_header->e_lfanew;
    ntSignature = *(ULONG *)ntSignature;
    if (IMAGE_NT_SIGNATURE != ntSignature) {
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
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 112);//PE32+文件.
    } else {
        p_image_data_directory = (IMAGE_DATA_DIRECTORY *)((ULONG)p_image_optional_header + 96);
    }

    //先清空子节点.
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        //如果存在就清除.
        if (g_htreeitem_data_directory[i]) {
            BOOL b = TreeView_DeleteItem(g_h_tree, g_htreeitem_data_directory[i]);
            if (!b) {
                int x = GetLastError();
                //return false;//其实这个失败无所谓,根本就不用检查.
            }
        }
    }

    //BOOL b = InvalidateRect(g_h_tree,0,0);//让改变立即显示.用上面的办法无效.

    int m = 0;
    int n = 0;
    for (; m < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; m++) //规范规定是从1开始的.
    {
        //如果这一项不为空,就显示对应的名字.这个也搞个枚举.
        if (p_image_data_directory[m].VirtualAddress && p_image_data_directory[m].Size) {
            TV_INSERTSTRUCT tvinsert;
            tvinsert.hParent = g_htreeitem[MOREINFORMATION];
            tvinsert.item.mask = TVIF_TEXT + TVIF_IMAGE + TVIF_SELECTEDIMAGE;//必须加这一行,不然不显示.
            tvinsert.item.pszText = g_table_name[m];
            g_htreeitem_data_directory[m] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);

            n++;//这个顺序不依赖i.
        }
    }

    BOOL b = InvalidateRect(g_h_tree, 0, 0);//让改变立即显示.用上面的办法无效.

    UnmapViewOfFile(pmz);
    CloseHandle(hfilemap);
    CloseHandle(hfile);

    return r;//返回值暂时没有意义.
}


void On_DropFiles(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    wchar_t szFileName[260] = {0};
    DragQueryFile((HDROP)wParam, 0, szFileName, sizeof(szFileName)); //只取一个文件，第二个参数可以设置为0。KmdManager.exe 就是这样实现的。

    //UINT cFiles = DragQueryFile((HDROP)wParam, (UINT)-1, NULL, 0);//这个个数没有用.

    BOOL b = PathIsDirectory(szFileName);
    //if (b == true) //00B4161A  cmp         dword ptr [ebp-268h],1
    //if (b == TRUE) //00B4161A  cmp         dword ptr [ebp-268h],1
    if (b) //cmp         dword ptr [ebp-268h],0  
    {
        g_IsValidPE = false;
        g_IsPE32Ex = false;

        SendMessage(g_h_edit_FilePath, WM_SETTEXT, 0, 0);
        SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)L"请拖拽一个PE文件过来!");

        //文件是:C:\Users\Administrator\Desktop\aasdasf,不论文件大小是否为0.返回值是0.
        MessageBox(0, szFileName, L"这是一个目录!,请选择一个文件", 0);
        //wchar_t buffer[260] = L"这是一个目录,请选择一个文件.";
        //SendMessage(g_h_edit_FilePath,WM_SETTEXT,0,(LPARAM)buffer); 
    } else {
        int r = IsValidPE(szFileName);

        if (r == 1) {
            g_IsValidPE = true;

            SendMessage(g_h_edit_FilePath, WM_SETTEXT, 0, (LPARAM)szFileName);

            bool b = IsPE32Ex(szFileName);
            if (b) {
                g_IsPE32Ex = true;

                wchar_t buffer[260] = L"这是一个pe32+文件.";
                SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)buffer);
            } else {
                wchar_t buffer[260] = L"这是一个pe32文件.";
                SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)buffer);

                g_IsPE32Ex = false;
            }
        } else {
            g_IsValidPE = false;
            g_IsPE32Ex = false;

            SendMessage(g_h_edit_FilePath, WM_SETTEXT, 0, (LPARAM)0);
            wchar_t buffer[260] = L"请拖拽一个PE文件过来!";
            SendMessage(g_h_static_prompt, WM_SETTEXT, 0, (LPARAM)buffer);

            if (r == 0) {
                MessageBox(0, szFileName, L"这不是一个有效的PE文件.", 0);
            } else {
                //可以考虑弹出个消息。
            }

            /*wchar_t buffer[260] = L"这不是一个pe文件.";
            SendMessage(g_h_static_prompt,WM_SETTEXT,0,(LPARAM)buffer);*/
        }

        //添加节数据下的子节点.
        bool b = AddSectionData(szFileName);

        //添加表下的子节点.
        b = AddMoreInformation(szFileName);// MOREINFORMATION
    }

    b = InvalidateRect(g_h_tree, 0, 0);//让改变立即显示.

    b = TreeView_Expand(g_h_tree, g_htreeitem[MOREINFORMATION], TVE_COLLAPSE);//折叠
    //b = TreeView_Expand(g_h_tree, g_htreeitem_data_directory[IMPORT], TVE_EXPAND);

    DragFinish((HDROP)wParam);
}


void On_Notify_Click(HWND hWnd, WPARAM wParam, LPARAM lParam) //控件的单击处理.
{
    //MessageBox(0,L"鼠标单击",L"树形控件消息",0);

    //HTREEITEM hTreeItem = TreeView_GetSelection(g_h_tree);//发现这个没有!
    //if (hTreeItem)
    //{
    //    //MessageBox(0,0,0,0);
    //    //TreeView_DeleteItem(hwndTreeView, hTreeItem);
    //}

    //hTreeItem = TreeView_GetSelection(((LPNMHDR)lParam)->hwndFrom);//用这个会出错.
    //if (hTreeItem)
    //{
    //    MessageBox(0,0,0,0);
    //}

    //方法一:
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
    //方法二:其实是一样的.

    if (((LPNMHDR)lParam)->hwndFrom == g_h_tree) //如果是树形控件,还有可能是列表控件.
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
        TCHAR buf[260] = {0};
        ti.cchTextMax = 260;
        ti.pszText = buf;
        ti.hItem = hItem;
        TreeView_GetItem(lpnmh->hwndFrom, &ti);

        /*
        其实这也可用一个函数完成:获取空间的字符,及文件路径,然后校验这个文件是否合法.
        加后面一个条件是:单击空白处,不弹出提示.
        */
        if (g_IsValidPE == false && lstrlen(buf) != 0) {
            MessageBox(0, L"请选择一个有效的PE文件", L"友好提示!", 0);
            return;
        }

        //1.如果是原来已知的树形控件的节点及子节点
        //比较每个节点,是某个节点,并选择相应的节点处理函数.

        //2.如果是节数据的子节点.
        //比较每个节点,是某个节点,并选择相应的节点处理函数.
        //这个节点的名字没有保存,可以根据名字再搜索一下,然后再定位.

        //3.如果是详细信息的子节点.
        //比较每个节点,是某个节点,并选择相应的节点处理函数.

        //如果是数据目录及详细信息。
        if (lstrcmpi(buf, g_tree_name[MOREINFORMATION]) == 0) {
            on_import();

            //下面还可能有更多的处理。

            BOOL b = InvalidateRect(g_h_tree, 0, 0);//让改变立即显示.用上面的办法无效.
        }


        //检查是不是数据目录的子节点。
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
                case EXPORT://其实这个也可以搞个枚举,
                    //On_Export(hWnd, wParam, lParam);//这个也可以搞个函数数组,对应上面的枚举.
                    break;
                case IMPORT: //其实也可以用这个:IMAGE_DIRECTORY_ENTRY_IMPORT系统自定义的..
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
                break;//这个可有可无.
            }//end if
        }//end for




    }//end if
}


void On_Notify_SelChanged(HWND hWnd, WPARAM wParam, LPARAM lParam)
/*
控件的选择的变化的处理.
这个暂时不用.
*/
{
    //MessageBox(0,L"选择改变",L"树形控件消息",0);

    HTREEITEM hTreeItem = TreeView_GetSelection(g_h_tree);
    if (hTreeItem) {
        //MessageBox(0,0,0,0);//这个也进入了.
    }

    //hTreeItem = TreeView_GetSelection(((LPNMHDR)lParam)->hwndFrom);
    if (hTreeItem) {
        //MessageBox(0,0,0,0);//这个也进入了.
    }

    TVITEM tvi;
    TCHAR szText[260] = {0};
    memset(&tvi, 0, sizeof(tvi));
    tvi.mask = TVIF_TEXT | TVIF_PARAM;
    tvi.hItem = hTreeItem;//g_h_tree;//the item handle;
    tvi.pszText = szText;
    tvi.cchTextMax = sizeof(szText);
    BOOL bSuccess = TreeView_GetItem(((LPNMHDR)lParam)->hwndFrom, &tvi);

    //MessageBox(0,tvi.pszText,0,0);//这个办法是正确的.
}


void On_Notify(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    switch (((LPNMHDR)lParam)->code) {
    case NM_CLICK://左键单击.后面常有改变的消息.
        On_Notify_Click(hWnd, wParam, lParam);
        break;
        //case NM_DBLCLK://左键双击击.前面常有单击的消息.
        //    MessageBox(0,L"鼠标双击",L"树形控件消息",0);
        //    break; 
        //case TVN_KEYDOWN ://点击键盘.
        //    MessageBox(0,L"键盘按下",L"树形控件消息",0);
        //    break; 
    case TVN_SELCHANGED://选择改变
    { //不加这个括号,在上面的条件下,也可以看到这里面的变量.
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
        SendMessage(hWnd, WM_SYSCOMMAND, SC_MOVE | HTCAPTION, 0);//支持拖动：或者SendMessage,hWnd,WM_NCLBUTTONDOWN,HTCAPTION,lParam        
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

    int hc = GetSystemMetrics(SM_CYCAPTION);//以像素计算的普通窗口标题的高度:19

    int xs = GetSystemMetrics(SM_CXSCREEN);
    int ys = GetSystemMetrics(SM_CYSCREEN);
    r.x = (xs - r.w) / 2;
    r.y = (ys - r.h /*这个是全屏居中,可以考虑减去任务栏的高度*/) / 2;//居中显示，如果x,y为负数，把x,y都设置为0.

    if (xs < 999 || ys < 768) {
        MessageBox(0, L"你的屏幕的分辨率过小,最小设置为:1024X768.请设置后重新运行程序.", L"友情提示", 0);
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
    UpdateWindow(hwndMain);//最好加上.

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {   //这里还可以加入快捷键：TranslateAccelerator，
        if (!TranslateAccelerator(msg.hwnd, 0, &msg)) //hAccelTable 支持快捷键和菜单。
        {
            TranslateMessage(&msg);//支持特殊的按键（字符）
            DispatchMessage(&msg);
        }
    }

    ExitProcess(0);
}