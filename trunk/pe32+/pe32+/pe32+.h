#pragma once

#include <Windows.h> 
#include <strsafe.h>

#include <commctrl.h>
#pragma comment(lib,"comctl32.lib")

#include <shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

enum PE_S
    /*
    这里是树形控件的已知的HTREEITEM.
    对应的还有相应的控件,如:列表框等.
    */
{
    DOS = 0,
    PESIGN,
    COFF,
    MY_OPTIONAL,
    STANDARD,//本来是想把这个和上面的值是相等的.
    SPECIFIC,// specific Specific
    DATADIRECTORIES,//DataDirectories 这个节点设计没有子节点.
    SECTIONTABLE,//SectionTable 这个节点设计没有子节点.
    SECTIONDATA,
    CERTIFICATEATTRIBUTE,//certificate attribute
    DEBUGINFORMATION,// debuginformation
    MOREINFORMATION,//这里是各种表的详细信息.
    EXPLAIN //explain 最后一个总是说明选项.
    //总共13个.
};

#define MAX_SECTION 96 //规范规定:Windows 加载器限制节的最大数目为 96.

enum data_directory
    /*
    数据目录的枚举常量,和数据目录里面的次序对应,最好有对应的函数.
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
    END //总共16个.最后一项为空.
};

typedef struct _RECTANGLE { 
    LONG x; 
    LONG y; 
    LONG w; 
    LONG h; 
} RECTANGLE, *PRECTANGLE; //rectangle