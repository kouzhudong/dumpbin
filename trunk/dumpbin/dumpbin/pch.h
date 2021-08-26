#pragma once

//#define _WIN32_WINNT 0x0501
//#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma warning(disable:28251)

#include <Winsock2.h>
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <crtdbg.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <fltuser.h>
#include <locale.h>
#include <Lmserver.h>
#include <stdarg.h>
#include <wincrypt.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <aclapi.h>
#include <VersionHelpers.h>
#include <ShlDisp.h>
#include <Shlobj.h>
#include <Softpub.h>
#include <mscat.h>
//#include <SubAuth.h>
//#include <LsaLookup.h>
#include <WinUser.h>
#include <direct.h>
#include <sddl.h>
#include <ws2tcpip.h>
#include <fwpsu.h>
#include <atlbase.h>
#include <mbnapi.h>
#include <iostream>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <atlconv.h>
#define _WS2DEF_
#include <mstcpip.h>
#include <Intshcut.h>
//#include <winternl.h>
#include <SubAuth.h>
//#include <NTSecAPI.h>
//#include <ntdef.h>
//#include <netioapi.h>
#include <inttypes.h>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Version.lib") 
//#pragma comment (lib,"Url.lib")

#include <imagehlp.h>//和DbgHelp.h有重复的定义。
#pragma comment(lib, "imagehlp.lib")

#include <bcrypt.h>
#pragma comment (lib, "Bcrypt.lib")

#include <ncrypt.h>
#pragma comment (lib, "Ncrypt.lib")

#include <wintrust.h>
#pragma comment (lib, "wintrust.lib")

#include <Setupapi.h>
#pragma comment (lib,"Setupapi.lib")

#include <Shlwapi.h>
#pragma comment (lib,"Shlwapi.lib")

//#include <DbgHelp.h>
#pragma comment (lib,"DbgHelp.lib")

#include <psapi.h>
#pragma comment(lib, "Psapi.lib")

#include <Sfc.h>
#pragma comment(lib, "Sfc.lib")

//#include <winsock.h>
#pragma comment(lib, "Ws2_32.lib")

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include <Userenv.h>
#pragma comment(lib, "Userenv.lib")

#include <Sensapi.h>
#pragma comment (lib,"Sensapi.lib")

#include <Wininet.h>
#pragma comment (lib,"Wininet.lib")

#include <string>
#include <list>
#include <regex>
using namespace std;


//////////////////////////////////////////////////////////////////////////////////////////////////

