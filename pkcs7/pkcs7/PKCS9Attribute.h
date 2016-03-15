#ifndef __CRYPTO_PKCS9_ATTRIBUTE_H__
#define __CRYPTO_PKCS9_ATTRIBUTE_H__

namespace tp{
    namespace crypto{
        class Object;
        class ObjectIdentifier;
        class DerValue;
        class PKCS9Attribute{
        public:
            PKCS9Attribute();
            virtual ~PKCS9Attribute();

            PKCS9Attribute(const ObjectIdentifier& oid, const Object& value);
            PKCS9Attribute(const char* name, const Object& value);
            PKCS9Attribute(DerValue& derVal);
            PKCS9Attribute(const PKCS9Attribute& other);
            void operator=(const PKCS9Attribute& other);

        private:
            void init(const ObjectIdentifier& oid, const Object& value);

        private:
            int m_index;
            Object* m_value;

        };
    }
}

#endif