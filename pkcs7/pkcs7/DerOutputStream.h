#ifndef __CRYPTO_DER_OUTPUT_STREAM_H__
#define __CRYPTO_DER_OUTPUT_STREAM_H__


#include "ByteArrayOutputStream.h"
namespace tp{
    namespace crypto{
        class OutputStream;
        class DerValue;
        class ObjectIdentifier;
        class DerOutputStream:public ByteArrayOutputStream{
        public:
            DerOutputStream(){}
            DerOutputStream(int size) :ByteArrayOutputStream(size){}

        public:
            void write(const std::vector<uint8_t>& data, int off, int len){
                ByteArrayOutputStream::write(data, off, len);
            }


            void write(uint8_t byte){ ByteArrayOutputStream::write(byte); }
            void write(uint8_t tag, const std::vector<uint8_t>& buf);
            void write(uint8_t tag, DerOutputStream& out);
            void writeImplicit(uint8_t tag, const DerOutputStream& value);
            void putDerValue(const DerValue& value);
            void putBoolean(bool value);
            void putEnumerated(int i);
            void putInteger(int i);
            void putBitString(const std::vector<uint8_t>& bits);
            void putOctetString(const std::vector<uint8_t>& octets);
            void putNull();
            void putOID(const ObjectIdentifier& oid);
            void putSequence(const std::vector<DerValue>& seq);
            void putSet(const std::vector<DerValue>& data);
            void putLength(int len);
            
            void putTag(uint8_t tagClass, bool isConstructed, uint8_t value);
            void derEncode(OutputStream& out);
        private:
            void putIntegerContents(int i);
            void writeString(const std::vector<uint8_t>& data, uint8_t tag, const std::string& encode);
        };
    }
}

#endif