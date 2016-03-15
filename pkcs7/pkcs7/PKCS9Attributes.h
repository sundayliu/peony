#ifndef __CRYPTO_PKCS9_ATTRIBUTES_H__
#define __CRYPTO_PKCS9_ATTRIBUTES_H__

#include <map>
#include <vector>
#include <inttypes.h>

#include "PKCS9Attribute.h"
#include "ObjectIdentifier.h"
namespace tp{
    namespace crypto{
        
        class DerInputStream;
        class PKCS9Attributes{
        public:
            PKCS9Attributes();
            PKCS9Attributes(const std::vector<ObjectIdentifier>& permittedAttributes, DerInputStream& in);
            PKCS9Attributes(DerInputStream& in, bool ignoreUnsupportedAttributes = false);
            PKCS9Attributes(const std::vector<PKCS9Attribute>& attributes);

        private:
            std::map<ObjectIdentifier, PKCS9Attribute> m_attributes;
            std::map<ObjectIdentifier, ObjectIdentifier> m_permittedAttributes;
            std::vector<uint8_t> m_encoding;
            bool m_ignoreUnsupportedAttributes;
        };
    }
}

#endif