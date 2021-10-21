#include "pch.h"
#include "openssl.h"
#include <openssl/crypto.h>


#pragma comment(lib, "libcrypto.lib")


//////////////////////////////////////////////////////////////////////////////////////////////////


int test()
{
    OPENSSL_die("Voluntary abort", __FILE__, __LINE__);
    return 0;
}
