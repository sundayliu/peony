#ifndef __CRYPTO_DER_VALUE_H__
#define __CRYPTO_DER_VALUE_H__

#include <string>
#include <vector>
#include <inttypes.h>

namespace tp{
    namespace crypto{
        class DerInputStream;
        class ObjectIdentifier;
        class DerInputBuffer;
        class DerOutputStream;

        class DerValue{
        public:
            bool isUniversal(){ return ((m_tag & 0x0c0) == 0x000); }
            bool isApplication(){ return ((m_tag & 0x0c0) == 0x040); }
            bool isContextSpecfic() { return ((m_tag & 0x0c0) == 0x080); }
            bool isContextSpecfic(uint8_t cntxTag){
                if (!isContextSpecfic()){
                    return false;
                }
                return ((m_tag & 0x01f) == cntxTag);
            }

            bool isPrivate(){ return ((m_tag & 0x0c0) == 0x0c0); }
            bool isConstructed() { return ((m_tag & 0x020) == 0x020); }
            bool isConstructed(uint8_t constructedTag){
                if (!isConstructed()){
                    return false;
                }

                return ((m_tag & 0x01f) == constructedTag);
            }
        public:
            DerValue(){};
            DerValue(const std::string& value);
            DerValue(const std::vector<uint8_t>& value);
            DerValue(uint8_t stringTag, const std::vector<uint8_t>& value);
            DerValue(uint8_t tag, std::vector<uint8_t>& data);
            DerValue(DerInputBuffer& input);
            DerValue(std::vector<uint8_t>& buf);
            DerValue(std::vector<uint8_t>& buf, int offset, int len);

        private:
            DerInputStream init(uint8_t stringTag, std::vector<uint8_t>& data);

        private:
            //DerInputStream init(bool fullyBuffered, DerInputStream)
        public:
            bool encode(DerOutputStream& out);
            DerInputStream* getData()const { return m_data; }
            uint8_t getTag()const{ return m_tag; }
            bool getBoolean(bool* out);
            bool getOID(ObjectIdentifier& oid);
            bool getOctetString(std::vector<uint8_t>& out);
            bool getInteger(int* out);
            bool getEnumerated(int* out);
            bool getAsString();
            bool getBitString();
            bool getDataBytes(std::vector<uint8_t>& out);
            bool getPrintableString();
            bool getT61String();
            bool getIA5String();
            bool getBMPString();
            bool getUTF8String();
            bool getGeneralizedString();
            bool getUTCTime();
            bool getGeneralizedTime();
            bool operator==(const DerValue& other);
            static bool doEquals(const DerValue& d1, const DerValue& d2);
            std::string toString(){
                std::string out = "DerValue TODO";
                return out;
            }

            bool toByteArray(std::vector<uint8_t>& out);
            bool toDerInputStream(DerInputStream& out);
            int getLength(){ return m_length; }

            // This list is based on X.680 (the ASN.1 spec)
            static bool isPrintableStringChar(char ch){
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')){
                    return true;
                }
                else{
                    switch (ch){
                    case ' ':
                    case '\'':
                    case '(':
                    case ')':
                    case ',':
                    case '+':
                    case '-':
                    case '*':
                    case '/':
                    case ':':
                    case '=':
                    case '?':
                        return true;
                    default:
                        return false;
                    }
                }
                return false;
            }
            static uint8_t createTag(uint8_t tagClass, bool isConstructed, uint8_t value){
                uint8_t tag = tagClass | value;
                if (isConstructed){
                    tag |= 0x020;
                }
                return tag;
            }
            void setTag(uint8_t tag){ m_tag = tag; }

        private:
            void append(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, std::vector<uint8_t>& out);

        public:
            static uint8_t TAG_UNIVERSAL;
            static uint8_t TAG_APPLICATION;
            static uint8_t TAG_CONTEXT;
            static uint8_t TAG_PRIVATE;

        public:
            static uint8_t tag_Boolean;
            static uint8_t tag_Integer;
            static uint8_t tag_BitString;
            static uint8_t tag_OctetString;
            static uint8_t tag_Null;
            static uint8_t tag_ObjectId;
            static uint8_t tag_Enumerated;
            static uint8_t tag_UTF8String;
            static uint8_t tag_PrintableString;
            static uint8_t tag_T61String;
            static uint8_t tag_IA5String;
            static uint8_t tag_UTCTime;
            static uint8_t tag_GeneralizedTime;
            static uint8_t tag_GeneralizedString;
            static uint8_t tag_UniveralString;
            static uint8_t tag_BMPString;
            static uint8_t tag_Sequence;
            static uint8_t tag_SequenceOf;
            static uint8_t tag_Set;
            static uint8_t tag_SetOf;

        private:
            int m_length;
            uint8_t m_tag;
            DerInputBuffer* m_buffer;
            DerInputStream* m_data;
        };
    }
}


#endif