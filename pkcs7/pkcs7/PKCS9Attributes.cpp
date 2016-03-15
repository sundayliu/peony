#include "PKCS9Attributes.h"
#include "PKCS9Attribute.h"
#include "DerInputStream.h"
#include "ObjectIdentifier.h"


namespace tp{
    namespace crypto{
        PKCS9Attributes::PKCS9Attributes(){
            m_ignoreUnsupportedAttributes = false;
        }

        PKCS9Attributes::PKCS9Attributes(const std::vector<PKCS9Attribute>& attributes){

        }

        PKCS9Attributes::PKCS9Attributes(DerInputStream& in, bool ignoreUnsupportedAttributes /* = false */){
            DerValue val = in.getDerValue();
            
        }

        PKCS9Attributes::PKCS9Attributes(const std::vector<ObjectIdentifier>& permittedAttributes, DerInputStream& in){

        }
    }
}