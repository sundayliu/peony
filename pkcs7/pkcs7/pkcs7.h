//////////////////////////////////////////////////////////////////////////////////////////////////
// @file: crypto/pkcs/pkcs7.h
// @author: sundayliu
// @date: 2016.01.17
//////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CRYPTO_PKCS_PKCS7_H__
#define __CRYPTO_PKCS_PKCS7_H__

#include <inttypes.h>
#include <string>
#include <vector>

#include "DerInputStream.h"

namespace tp{
namespace crypto{

    class Serializable{

    };

    class ObjectIdentifier : public Serializable{

    };

    class BigInteger{

    };

    class AlgorithmId{

    };

    class ContentInfo{

    };

    class X509Certificate{

    };

    class X509CRL{

    };

    class SignerInfo{

    };

    class Principal{

    };

    class OutputStream{

    };

    class DerOutputStream{

    };

    class X500Name{

    };
class PKCS7{
public:
    PKCS7(const std::string& filename);
    PKCS7(const uint8_t* data, size_t len);
    ~PKCS7();
    
    bool isValid(){return m_valid;}

public:
    void encodeSignedData(OutputStream& out);
    void encodeSignedData(DerOutputStream& out);
    SignerInfo verify(SignerInfo& info, uint8_t* bytes, size_t size);
    std::vector<SignerInfo> verify(uint8_t* bytes, size_t size);
    std::vector<SignerInfo> verify();

public:
    BigInteger getVersion(){
        return m_version;
    }

    std::vector<AlgorithmId> getDigestAlgorithmIds(){
        return m_digestAlgorithmIds;
    }

    ContentInfo getContentInfo(){
        return m_contentInfo;
    }

    std::vector<X509Certificate> getCertificates(){
        return m_certificates;
    }

    std::vector<X509CRL> getCRLs(){
        return m_crls;
    }

    std::vector<SignerInfo> getSignerInfos(){
        return m_signerInfos;
    }

    std::string toString();

    X509Certificate getCertificate(const BigInteger& serial, const X500Name& issuerName);

    bool isOldStyle(){
        return m_oldStyle;
    }
    
private:
    bool parse(const DerInputStream& derin);
    bool parse(const DerInputStream& derin, bool oldStyle);
    bool parse();
    PKCS7(const PKCS7&);
    PKCS7& operator=(const PKCS7&);
private:
    uint8_t* m_data;
    size_t m_data_size;
    bool m_valid;
    std::string m_filename;

private:
    ObjectIdentifier m_contentType;
    BigInteger m_version;
    std::vector<AlgorithmId> m_digestAlgorithmIds;
    ContentInfo m_contentInfo;
    std::vector<X509Certificate> m_certificates;
    std::vector<X509CRL> m_crls;
    std::vector<SignerInfo> m_signerInfos;
    std::vector<Principal> m_certIssuerNames;
    bool m_oldStyle;
};

}
}

#endif //__CRYPTO_PKCS_PKCS7_H__
