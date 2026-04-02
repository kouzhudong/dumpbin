#include "import.h"
#include "pe32+.h"
#include "pe.h"

extern bool g_IsPE32Ex;
extern HTREEITEM g_htreeitem_data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
extern HWND g_h_tree;
extern HTREEITEM g_htreeitem[EXPLAIN + 1];
extern wchar_t * g_table_name[];
extern HWND g_h_edit_FilePath;

#define MAX_IMPORT_DLL 260

HTREEITEM h_tree_import_dllname[MAX_IMPORT_DLL] = {0};

unsigned int RVATOOFFSET(IN wchar_t * filename, IN unsigned int rva)
{
    unsigned int offset = 0;

    PEFileMap pe;
    if (!pe.Open(filename, g_IsPE32Ex, true)) {
        return 0;
    }

    for (int i = 0; i < pe.coff->NumberOfSections; i++) {
        if (rva >= pe.sections[i].VirtualAddress &&
            rva <= (pe.sections[i].VirtualAddress + pe.sections[i].Misc.VirtualSize)) {
            offset = rva - pe.sections[i].VirtualAddress + pe.sections[i].PointerToRawData;
            break;
        }
    }

    return offset;
}


bool on_import()
{
    wchar_t wszfilename[_MAX_PATH] = {0};
    if (GetWindowText(g_h_edit_FilePath, wszfilename, _ARRAYSIZE(wszfilename)) == 0) {
        return false;
    }

    PEFileMap pe;
    if (!pe.Open(wszfilename, g_IsPE32Ex, false, true)) {
        return false;
    }

    //Import is the second entry in data directory, skip one entry
    IMAGE_DATA_DIRECTORY * p_import_dir = &pe.datadirs[IMAGE_DIRECTORY_ENTRY_IMPORT];

    for (int i = 0; i < MAX_IMPORT_DLL; i++) {
        if (h_tree_import_dllname[i]) {
            TreeView_DeleteItem(g_h_tree, h_tree_import_dllname[i]);
            h_tree_import_dllname[i] = NULL;
        }
    }

    InvalidateRect(g_h_tree, 0, 0);

    unsigned int importOffset = RVATOOFFSET(wszfilename, p_import_dir->VirtualAddress);
    if (importOffset == 0) {
        return false;
    }

    PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pe.pmz + importOffset);

    for (int i = 0; i < MAX_IMPORT_DLL; i++) {
        if (piid[i].Name == NULL) {
            break;
        }

        unsigned int nameOffset = RVATOOFFSET(wszfilename, piid[i].Name);
        if (nameOffset == 0) {
            break;
        }
        char * dllname = (char *)((ULONG_PTR)pe.pmz + nameOffset);

        wchar_t wszDllName[MAX_PATH] = {0};
        if (MultiByteToWideChar(CP_ACP, 0, (LPCSTR)dllname, lstrlenA((LPCSTR)dllname), wszDllName, _ARRAYSIZE(wszDllName)) == 0) {
            break;
        }

        TV_INSERTSTRUCT tvinsert;
        tvinsert.hParent = g_htreeitem_data_directory[IMPORT];
        tvinsert.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
        tvinsert.item.pszText = wszDllName;
        h_tree_import_dllname[i] = (HTREEITEM)SendMessage(g_h_tree, TVM_INSERTITEM, 0, (LPARAM)&tvinsert);
    }

    InvalidateRect(g_h_tree, 0, 0);

    return true;
}
