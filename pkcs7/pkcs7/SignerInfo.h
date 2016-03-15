#ifndef __CRYPTO_SIGNER_INFO_H__
#define __CRYPTO_SIGNER_INFO_H__

#include <vector>
#include <inttypes.h>
#include "PKCS9Attributes.h"
#include "BigInteger.h"
#include "DerValue.h"
#include "DerInputStream.h"
#include "AlgorithmId.h"

namespace tp{
    namespace crypto{
        class SignerInfo{
        public:
            SignerInfo();
            SignerInfo(DerInputStream& derin, bool oldStyle = false);

        private:
            BigInteger m_version;
            DerValue m_issuerName;
            BigInteger m_certificateSerialNumber;
            AlgorithmId m_digestAlgorithmId;
            AlgorithmId m_digestEncryptionAlgorithmId;
            std::vector<uint8_t> m_encryptedDigest;
            PKCS9Attributes m_authenticatedAttributes;
            PKCS9Attributes m_unauthenticateAttributes;
        };
    }
}

#endif