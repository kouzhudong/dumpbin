# dumpbin
Dump Microsoft Portable Executable (PE) Files Information

本工程的特色：
1. 支持的比较全，除了PE，还有：COFF，NE，LE等文件格式。不支持ELF，APK等格式。
2. 解析的比较全，所有的DIRECTORY_ENTRIES都解析了。
3. SECURITY/数字证书解析的比较深入和全面，用了好几种解析的办法。
4. 用到了反汇编引擎，这不是本工程的特色。备注：Zydis。
5. 用到了openssl, tiny-asn1等第三方的库。
