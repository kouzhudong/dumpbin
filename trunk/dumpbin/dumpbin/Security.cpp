#include "pch.h"
#include "Security.h"
#include "Public.h"
#include "openssl.h"
#include "Public.h"


#pragma warning(disable:6386)
#pragma warning(disable:6387)


//////////////////////////////////////////////////////////////////////////////////////////////////


PCSTR GetCertificateType(_In_ WORD CertificateType)
{
    PCSTR CertificateTypeStr = NULL;

    switch (CertificateType) {
    case WIN_CERT_TYPE_X509:
        CertificateTypeStr = "X509";
        break;
    case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        CertificateTypeStr = "PKCS_SIGNED_DATA";
        break;
    case WIN_CERT_TYPE_RESERVED_1:
        CertificateTypeStr = "RESERVED_1";
        break;
    case WIN_CERT_TYPE_TS_STACK_SIGNED:
        CertificateTypeStr = "TS_STACK_SIGNED";
        break;
    default:
        CertificateTypeStr = "未知";
        break;
    }

    return CertificateTypeStr;
}


PCSTR GetCertRevision(_In_ WORD wRevision)
{
    PCSTR string = NULL;

    switch (wRevision) {
    case WIN_CERT_REVISION_1_0:
        string = "1_0";
        break;
    case WIN_CERT_REVISION_2_0:
        string = "2_0";
        break;
    default:
        string = "未知";
        break;
    }

    return string;
}


BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext)
{
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData;

    __try {
        //可考虑用openssl的方式处理pCertContext->cbCertEncoded + pCertContext->pbCertEncoded。

        _tprintf(_T("CertEncodingType:%d.\n"), pCertContext->dwCertEncodingType);

        _tprintf(_T("Version:%d.\n"), pCertContext->pCertInfo->dwVersion + 1);

        _tprintf(_T("ObjId:%hs.\n"), pCertContext->pCertInfo->SignatureAlgorithm.pszObjId);

        _tprintf(_T("Parameters: "));
        dwData = pCertContext->pCertInfo->SignatureAlgorithm.Parameters.cbData;
        for (DWORD n = 0; n < dwData; n++) {
            _tprintf(_T("%02x "), pCertContext->pCertInfo->SignatureAlgorithm.Parameters.pbData[n]);
        }
        _tprintf(_T("\n"));

        // Print Serial Number.
        _tprintf(_T("Serial Number: "));
        dwData = pCertContext->pCertInfo->SerialNumber.cbData;
        for (DWORD n = 0; n < dwData; n++) {
            _tprintf(_T("%02x "), pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
        }
        _tprintf(_T("\n"));

        char NotBefore[MAX_PATH] = {0};
        FileTimeToLocalTimeA(&pCertContext->pCertInfo->NotBefore, NotBefore);
        printf("有效期从:%s\t", NotBefore);

        char NotAfter[MAX_PATH] = {0};
        FileTimeToLocalTimeA(&pCertContext->pCertInfo->NotAfter, NotAfter);
        printf("到:%s\n", NotAfter);

        _tprintf(_T("SubjectPublicKey Algorithm ObjId:%hs.\n"), 
                 pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);

        _tprintf(_T("SubjectPublicKey Algorithm Parameters: "));
        dwData = pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.cbData;
        for (DWORD n = 0; n < dwData; n++) {
            _tprintf(_T("%02x "), 
                     pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.pbData[dwData - (n + 1)]);
        }
        _tprintf(_T("\n"));

        //pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData
        //pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData
        //pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cUnusedBits

        //还有IssuerUniqueId，SubjectUniqueId，cExtension等信息。

        _tprintf(_T("cExtension:%d.\n"), pCertContext->pCertInfo->cExtension);
        _tprintf(_T("Extension ObjId:%hs.\n"), pCertContext->pCertInfo->rgExtension->pszObjId);
        _tprintf(_T("Extension fCritical:%d.\n"), pCertContext->pCertInfo->rgExtension->fCritical);
        _tprintf(_T("Extension Value: "));
        dwData = pCertContext->pCertInfo->rgExtension->Value.cbData;
        for (DWORD n = 0; n < dwData; n++) {
            _tprintf(_T("%02x "), pCertContext->pCertInfo->rgExtension->Value.pbData[n]);
        }
        _tprintf(_T("\n"));

        // Get Issuer name size.
        if (!(dwData = CertGetNameString(pCertContext,
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         CERT_NAME_ISSUER_FLAG,
                                         NULL,
                                         NULL,
                                         0))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for Issuer name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for issuer name.\n"));
            __leave;
        }

        // Get Issuer name.
        if (!(CertGetNameString(pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                CERT_NAME_ISSUER_FLAG,
                                NULL,
                                szName,
                                dwData))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // print Issuer name.
        _tprintf(_T("Issuer Name: %s\n"), szName);
        LocalFree(szName);
        szName = NULL;

        // Get Subject name size.
        if (!(dwData = CertGetNameString(pCertContext,
                                         CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                         0,
                                         NULL,
                                         NULL,
                                         0))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Allocate memory for subject name.
        szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
        if (!szName) {
            _tprintf(_T("Unable to allocate memory for subject name.\n"));
            __leave;
        }

        // Get subject name.
        if (!(CertGetNameString(pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                NULL,
                                szName,
                                dwData))) {
            _tprintf(_T("CertGetNameString failed.\n"));
            __leave;
        }

        // Print Subject Name.
        _tprintf(_T("Subject Name: %s\n"), szName);

        DWORD dwStrType = CERT_X500_NAME_STR;
        DWORD dwCount = CertGetNameString(pCertContext,
                                          CERT_NAME_RDN_TYPE,
                                          0,
                                          &dwStrType,
                                          NULL,
                                          0);
        if (dwCount) {
            LPTSTR szSubjectRDN = (LPTSTR)LocalAlloc(0, dwCount * sizeof(TCHAR));
            dwCount = CertGetNameString(pCertContext,
                                        CERT_NAME_RDN_TYPE,
                                        0,
                                        &dwStrType,
                                        szSubjectRDN,
                                        dwCount);
            if (dwCount) {
                _tprintf(_T("Certificate Subject = %s\n"), szSubjectRDN);
            }

            LocalFree(szSubjectRDN);
        }

        fReturn = TRUE;
    } __finally {
        if (szName != NULL) 
            LocalFree(szName);
    }

    return fReturn;
}


void DecodeCertificate(PBYTE Certificate, DWORD Length)
/*
功能：用CryptDecodeObjectEx解码PKCS#7 SignedData的ASN1结构。
*/
{
    //  Get the length needed for the decoded buffer.
    DWORD cbDecoded = NULL;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            PKCS_CONTENT_INFO,//X509_NAME
                            Certificate,     // the buffer to be decoded
                            Length,
                            CRYPT_DECODE_NOCOPY_FLAG,
                            NULL,
                            NULL,
                            &cbDecoded)) {
        //printf("The needed buffer length is %d\n", cbDecoded);
    } else {
        _ASSERTE(false);
    }    

    // Allocate memory for the decoded information.
    BYTE * pbDecoded;
    if (!(pbDecoded = (BYTE *)malloc(cbDecoded))) {
        _ASSERTE(false);
    }

    // Decode the encoded buffer.
    if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            PKCS_CONTENT_INFO,//X509_NAME
                            Certificate,     // the buffer to be decoded
                            Length,
                            CRYPT_DECODE_NOCOPY_FLAG,
                            NULL,
                            pbDecoded,
                            &cbDecoded)) {
        CRYPT_CONTENT_INFO * content_info = (CRYPT_CONTENT_INFO *)pbDecoded;
        if (content_info) {
            printf("ObjId:%s\n", content_info->pszObjId);

            //WCHAR szSubject[1024] = {0};//d2i_X509_NAME  +  X509_NAME_oneline
            //DWORD cbSize = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            //                             &content_info->Content,
            //                             CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
            //                             szSubject,
            //                             sizeof(szSubject));
            //if (cbSize > 1) {//  If it returns one, the name is an empty string.
            //    ///printf("szSubject：%ls\n", szSubject);//内容为空。
            //} else {
            //    _ASSERTE(false);
            //}

            HCERTSTORE CertStore = NULL;
            HCRYPTMSG Msg = NULL;
            CryptQueryObject(CERT_QUERY_OBJECT_BLOB,
                             &content_info->Content,
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                             CERT_QUERY_FORMAT_FLAG_BINARY,
                             0,
                             NULL,
                             NULL,
                             NULL,
                             &CertStore,
                             &Msg,
                             NULL);

            PCCERT_CONTEXT PrevCertContext = NULL;
            while ((PrevCertContext = CertEnumCertificatesInStore(CertStore, PrevCertContext)) != NULL) {
                printf("\n");
                PrintCertificateInfo(PrevCertContext);
            }
        } else {
            _ASSERTE(false);
        }
    } else {
        _ASSERTE(false);
    }
}


void PrintSecurity(LPWIN_CERTIFICATE SecurityDirectory)
{
    printf("Length:%d.\r\n", SecurityDirectory->dwLength);
    printf("Revision:%d(%s).\r\n",
           SecurityDirectory->wRevision,
           GetCertRevision(SecurityDirectory->wRevision));
    printf("CertificateType:%d(%s).\r\n",
           SecurityDirectory->wCertificateType,
           GetCertificateType(SecurityDirectory->wCertificateType));

    switch (SecurityDirectory->wCertificateType) {
    case WIN_CERT_TYPE_X509://bCertificate 包含的是 X.509 证书

        break;
    case WIN_CERT_TYPE_PKCS_SIGNED_DATA://bCertificate 包含的是 PKCS#7 SignedData 结构
    {
        //这个数据是啥结构呢？
        //以前的经验是里面有utf8编码。
        PBYTE Certificate = SecurityDirectory->bCertificate;

        /*
        这里的数据可用CryptDecodeObjectEx解析不？
        这应该是ASN格式的。
        注意：数据结构CERT_ALT_NAME_ENTRY。

        这里的数据可以用openssl的函数解析，如：d2i_PKCS7等。
        参考：https://github.com/ajkhoury/CertDump.git
        */

        DecodeCertificate(Certificate, SecurityDirectory->dwLength);

        break;
    }
    case WIN_CERT_TYPE_RESERVED_1://保留。 

        break;
    case WIN_CERT_TYPE_TS_STACK_SIGNED://终端服务器协议栈证书签名

        break;
    default:

        break;
    }

    printf("\r\n");
}


BOOL WINAPI DigestFunction(DIGEST_HANDLE refdata, PBYTE pData, DWORD dwLength)
//这个会被调用多次。
{

    return true;
}


void ParseCertificateInfo1()
/*
用系统的API解析下证书的信息，以便和自己解析的对比。

这种方式没有分析PE文件的DataDirectory。
*/
{
    int Args;
    LPWSTR * Arglist = CommandLineToArgvW(GetCommandLineW(), &Args);

    LPCWSTR FileName = Arglist[2];

    HANDLE hfile = INVALID_HANDLE_VALUE;
    LPWIN_CERTIFICATE buffer = NULL;

    __try {
        hfile = CreateFile(FileName,
                           FILE_READ_DATA | FILE_WRITE_DATA,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (hfile == INVALID_HANDLE_VALUE) {
            int x = GetLastError();
            __leave;
        }

        DWORD CertificateCount = 0;
        DWORD Indices[9] = {0};
        DWORD  IndexCount = ARRAYSIZE(Indices);
        BOOL ret = ImageEnumerateCertificates(hfile,
                                              CERT_SECTION_TYPE_ANY,
                                              &CertificateCount,
                                              Indices,
                                              IndexCount);
        if (!ret) {
            int x = GetLastError();
            __leave;
        }

        for (DWORD i = 0; i < CertificateCount; i++) {
            WIN_CERTIFICATE Certificateheader = {0};
            ret = ImageGetCertificateHeader(hfile, i, &Certificateheader);
            if (!ret) {
                int x = GetLastError();
            }

            WIN_CERTIFICATE Certificate = {0};
            DWORD RequiredLength = sizeof(WIN_CERTIFICATE);
            ret = ImageGetCertificateData(hfile, i, &Certificate, &RequiredLength);
            if (!ret) {
                int x = GetLastError();
            }

            buffer = (LPWIN_CERTIFICATE)HeapAlloc(GetProcessHeap(), 0, RequiredLength);
            _ASSERTE(buffer);

            ret = ImageGetCertificateData(hfile, i, buffer, &RequiredLength);
            _ASSERTE(ret);

            CRYPT_DATA_BLOB p7Data;
            p7Data.cbData = RequiredLength - sizeof(DWORD) - sizeof(WORD) - sizeof(WORD);
            p7Data.pbData = buffer->bCertificate;
            HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_PKCS7,
                                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              NULL,
                                              0,
                                              &p7Data);
            if (hStore) {
                int count = 0;
                char szCodeSigningOID[] = szOID_PKIX_KP_CODE_SIGNING;
                // populate the key usage structure with the Code Signing OID
                CERT_ENHKEY_USAGE keyUsage;
                keyUsage.cUsageIdentifier = 1;
                keyUsage.rgpszUsageIdentifier = (LPSTR *)LocalAlloc(0, sizeof(LPSTR));
                keyUsage.rgpszUsageIdentifier[0] = &szCodeSigningOID[0];

                // Find certificates that contain the Code Signing Enhanced Key Usage
                PCCERT_CONTEXT  pCertContext = NULL;
                do {
                    pCertContext = CertFindCertificateInStore(hStore,
                                                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                              CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                                                              CERT_FIND_ENHKEY_USAGE,
                                                              &keyUsage,
                                                              pCertContext);
                    if (pCertContext) {
                        count++;
                        PrintCertificateInfo(pCertContext);
                    }
                } while (pCertContext);

                if (count == 0) {
                    _tprintf(_T("No Code Signing certificates found\n"));
                }

                LocalFree(keyUsage.rgpszUsageIdentifier);
                CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
            } else {
                _tprintf(_T("CertOpenStore failed with error 0x%.8X\n"), GetLastError());
            }

            DIGEST_HANDLE DigestHandle = NULL;
            ret = ImageGetDigestStream(hfile, i, DigestFunction, DigestHandle);
            if (!ret) {
                int x = GetLastError();
            }

            HeapFree(GetProcessHeap(), 0, buffer);
        }
    } __finally {
        if (INVALID_HANDLE_VALUE != hfile) {
            CloseHandle(hfile);
        }
    }

    LocalFree(Arglist);
}


void ParseCertificateInfo2(PIMAGE_DATA_DIRECTORY DataDirectory, LPWIN_CERTIFICATE SecurityDirectory)
/*

此方式的效果类似：signtool.exe verify /pa /a /v c:\windows\notepad.exe，但比这个更强更多。

从分析PE文件的DataDirectory开始，一步一步的解析。
*/
{
    for (DWORD i = 0; i < DataDirectory->Size; ) {
        SecurityDirectory = LPWIN_CERTIFICATE((PBYTE)SecurityDirectory + i);

        printf("index:%d.\r\n", i + 1);

        PrintSecurity(SecurityDirectory);

        DWORD dwLength = SecurityDirectory->dwLength / 8;

        if (SecurityDirectory->dwLength % 8) {
            dwLength++;
        }

        i += dwLength * 8;
    }
}


void ParseCertificateInfo3()
/*
用openssl解析PE的证书。
*/
{
 
}


DWORD Security(_In_ PBYTE Data, _In_ DWORD Size)
/*
参考：\win2k\trunk\private\sdktools\imagehlp\dice.cxx的FindCertificate函数。
*/
{
    DWORD ret = ERROR_SUCCESS;

    if (!IsValidPE(Data, Size)) {
        return ret;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = {0};
    GetDataDirectory(Data, Size, IMAGE_DIRECTORY_ENTRY_SECURITY, &DataDirectory);

    if (0 == DataDirectory.VirtualAddress) {
        printf("此文件没有Security.\r\n");
        return ret;
    }

    printf("Security Directory Information:\r\n");
    printf("VirtualAddress:%#010X.\r\n", DataDirectory.VirtualAddress);
    printf("Size:%#010X.\r\n", DataDirectory.Size);
    printf("\r\n");

    //////////////////////////////////////////////////////////////////////////////////////////////

    //ULONG size = 0;
    //PIMAGE_SECTION_HEADER FoundHeader = NULL;
    //LPWIN_CERTIFICATE SecurityDirectory = (LPWIN_CERTIFICATE)
    //    ImageDirectoryEntryToDataEx(Data,
    //                                FALSE,//自己映射的用FALSE，操作系统加载的用TRUE。 
    //                                IMAGE_DIRECTORY_ENTRY_SECURITY,
    //                                &size,
    //                                &FoundHeader);

    LPWIN_CERTIFICATE SecurityDirectory = (LPWIN_CERTIFICATE)(Data + DataDirectory.VirtualAddress);

    PIMAGE_NT_HEADERS NtHeaders = ImageNtHeader(Data);
    _ASSERTE(NtHeaders);

    //////////////////////////////////////////////////////////////////////////////////////////////

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式一：\n");

    ParseCertificateInfo1();

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式二：\n");

    ParseCertificateInfo2(&DataDirectory, SecurityDirectory);

    printf("----------------------------------------------------------------------------------\n");
    printf("解析方式三：\n");

    ParseCertificateInfo3();

    //////////////////////////////////////////////////////////////////////////////////////////////

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD Security(_In_ LPCWSTR FileName)
{
    return MapFile(FileName, Security);
}
