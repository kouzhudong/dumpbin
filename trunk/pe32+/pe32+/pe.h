#pragma once

#include <Windows.h>

struct PEFileMap
{
    HANDLE hfile;
    HANDLE hfilemap;
    LPVOID pmz;

    IMAGE_DOS_HEADER * dos;
    IMAGE_FILE_HEADER * coff;
    IMAGE_OPTIONAL_HEADER * optional;
    IMAGE_SECTION_HEADER * sections;
    IMAGE_DATA_DIRECTORY * datadirs;

    PEFileMap() : hfile(INVALID_HANDLE_VALUE), hfilemap(NULL), pmz(NULL),
        dos(NULL), coff(NULL), optional(NULL), sections(NULL), datadirs(NULL) {}

    ~PEFileMap() { Close(); }

    void Close()
    {
        if (pmz) { UnmapViewOfFile(pmz); pmz = NULL; }
        if (hfilemap) { CloseHandle(hfilemap); hfilemap = NULL; }
        if (hfile != INVALID_HANDLE_VALUE) { CloseHandle(hfile); hfile = INVALID_HANDLE_VALUE; }
        dos = NULL; coff = NULL; optional = NULL; sections = NULL; datadirs = NULL;
    }

    bool Open(const wchar_t * filename, bool isPE32Plus = false, bool parse_sections = false, bool parse_datadirs = false)
    {
        hfile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hfile == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD FileSizeHigh;
        DWORD FileSizeLow = GetFileSize(hfile, &FileSizeHigh);
        if (FileSizeLow == 0 && FileSizeHigh == 0) {
            Close();
            return false;
        }

        hfilemap = CreateFileMapping(hfile, NULL, PAGE_READONLY, NULL, NULL, NULL);
        if (hfilemap == NULL) {
            Close();
            return false;
        }

        pmz = MapViewOfFile(hfilemap, SECTION_MAP_READ, NULL, NULL, 0);
        if (pmz == NULL) {
            Close();
            return false;
        }

        dos = (IMAGE_DOS_HEADER *)pmz;
        if (IMAGE_DOS_SIGNATURE != dos->e_magic) {
            Close();
            return false;
        }

        ULONG_PTR ntSigAddr = (ULONG_PTR)dos + dos->e_lfanew;
        ULONG ntSignature = *(ULONG *)ntSigAddr;
        if (IMAGE_NT_SIGNATURE != ntSignature) {
            Close();
            return false;
        }

        coff = (IMAGE_FILE_HEADER *)(ntSigAddr + sizeof(ULONG));
        optional = (IMAGE_OPTIONAL_HEADER *)((ULONG_PTR)coff + sizeof(IMAGE_FILE_HEADER));

        if (parse_sections) {
            sections = (IMAGE_SECTION_HEADER *)((ULONG_PTR)optional + coff->SizeOfOptionalHeader);
        }

        if (parse_datadirs) {
            SIZE_T offset = isPE32Plus ?
                FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, DataDirectory) :
                FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory);
            datadirs = (IMAGE_DATA_DIRECTORY *)((ULONG_PTR)optional + offset);
        }

        return true;
    }

private:
    PEFileMap(const PEFileMap &);
    PEFileMap & operator=(const PEFileMap &);
};
