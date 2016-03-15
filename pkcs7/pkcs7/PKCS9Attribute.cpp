#include "PKCS9Attribute.h"
#include "DerValue.h"
#include "Object.h"
#include "ObjectIdentifier.h"

namespace tp{
    namespace crypto{
        PKCS9Attribute::PKCS9Attribute(){
            m_index = 0;
            m_value = NULL;
        }

        PKCS9Attribute::~PKCS9Attribute(){
            if (m_value != NULL){
                delete m_value;
                m_value = NULL;
            }
        }

        PKCS9Attribute::PKCS9Attribute(const ObjectIdentifier& oid, const Object& value){

        }

        PKCS9Attribute::PKCS9Attribute(const char* name, const Object& value){

        }

        PKCS9Attribute::PKCS9Attribute(DerValue& derVal){

        }

        void PKCS9Attribute::init(const ObjectIdentifier& oid, const Object& value){

        }

        PKCS9Attribute::PKCS9Attribute(const PKCS9Attribute& other){

        }

        void PKCS9Attribute::operator=(const PKCS9Attribute& other){

        }


    }
}