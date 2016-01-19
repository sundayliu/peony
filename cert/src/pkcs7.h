//////////////////////////////////////////////////////////////////////////////////////////////////
// @file: crypto/pkcs/pkcs7.h
// @author: sundayliu
// @date: 2016.01.17
//////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CRYPTO_PKCS_PKCS7_H__
#define __CRYPTO_PKCS_PKCS7_H__

#include <inttypes.h>
#include <string>

namespace tp{
namespace crypto{


class PKCS7{
public:
    PKCS7(const std::string& filename);
    PKCS7(const uint8_t* data, size_t len);
    ~PKCS7();
    
    bool isValid(){return m_valid;}
    
private:
    bool parse();
    PKCS7(const PKCS7&);
    PKCS7& operator=(const PKCS7&);
private:
    uint8_t* m_data;
    size_t m_data_size;
    bool m_valid;
    std::string m_filename;
};

}
}

#endif //__CRYPTO_PKCS_PKCS7_H__
