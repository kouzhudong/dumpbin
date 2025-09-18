#pragma once

#include <Windows.h> 
#include <strsafe.h>

#include <commctrl.h>
#pragma comment(lib,"comctl32.lib")

#include <shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

enum PE_S
    /*
    ���������οؼ�����֪��HTREEITEM.
    ��Ӧ�Ļ�����Ӧ�Ŀؼ�,��:�б���.
    */
{
    DOS = 0,
    PESIGN,
    COFF,
    MY_OPTIONAL,
    STANDARD,//�������������������ֵ����ȵ�.
    SPECIFIC,// specific Specific
    DATADIRECTORIES,//DataDirectories ����ڵ����û���ӽڵ�.
    SECTIONTABLE,//SectionTable ����ڵ����û���ӽڵ�.
    SECTIONDATA,
    CERTIFICATEATTRIBUTE,//certificate attribute
    DEBUGINFORMATION,// debuginformation
    MOREINFORMATION,//�����Ǹ��ֱ����ϸ��Ϣ.
    EXPLAIN //explain ���һ������˵��ѡ��.
    //�ܹ�13��.
};

#define MAX_SECTION 96 //�淶�涨:Windows ���������ƽڵ������ĿΪ 96.

enum data_directory
    /*
    ����Ŀ¼��ö�ٳ���,������Ŀ¼����Ĵ����Ӧ,����ж�Ӧ�ĺ���.
    */
{
    EXPORT = 0, //Export
    IMPORT,//Import
    RESOURCE,//Resource
    EXCEPTION,//Exception
    CERTIFICATE,//Certificate
    BASE_RELOCATION,// Base Relocation
    DEBUG,//Debug
    ARCHITECTURE,//Architecture 
    CLOBAL_PTR,//Global Ptr 
    TLS,//TLS
    LOAD_CONFIG,// Load Config 
    BOUND_INPORT,//Bound Import 
    IAT ,//IAT 
    DELAY_INPORT_DESCRIPTOR, //Delay Import Descriptor
    CLR_RUNTIME_HEADER,//CLR Runtime Header 
    END //�ܹ�16��.���һ��Ϊ��.
};

typedef struct _RECTANGLE { 
    LONG x; 
    LONG y; 
    LONG w; 
    LONG h; 
} RECTANGLE, *PRECTANGLE; //rectangle