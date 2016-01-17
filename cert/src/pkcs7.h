//////////////////////////////////////////////////////////////////////////////////////////////////
// @file: crypto/pkcs/pkcs7.h
// @author: sundayliu
// @date: 2016.01.17
//////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CRYPTO_PKCS_PKCS7_H__
#define __CRYPTO_PKCS_PKCS7_H__

#include <inttypes.h>

namespace tp{
namespace crypto{


class PKCS7{
public:
    PKCS7();
    ~PKCS7();
    
private:
    uint8_t* m_data;
};

}
}

#endif //__CRYPTO_PKCS_PKCS7_H__
