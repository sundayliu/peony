#include "SignerInfo.h"
#include "PKCS9Attributes.h"
#include "BigInteger.h"
#include "DerValue.h"
#include "DerInputStream.h"

namespace tp{
    namespace crypto{
        SignerInfo::SignerInfo(){

        }

        SignerInfo::SignerInfo(DerInputStream& derin, bool oldStyle){
            m_version = derin.getBigInteger();
            std::vector<DerValue> issuerAndSerialNumber;
            derin.getSequence(2, issuerAndSerialNumber);

            DerValue tmp = derin.getDerValue();
            m_digestAlgorithmId = AlgorithmId::parse(tmp);

            if (derin.peekByte() == 0xA0){
                m_authenticatedAttributes = PKCS9Attributes(derin);
            }

            tmp = derin.getDerValue();
            m_digestEncryptionAlgorithmId = AlgorithmId::parse(tmp);
            
            derin.getOctetString(m_encryptedDigest);
            if (derin.available() != 0 && derin.peekByte() == 0xA1){
                m_unauthenticateAttributes = PKCS9Attributes(derin, true);
            }
        }
    }
}