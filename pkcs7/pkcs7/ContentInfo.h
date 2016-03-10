#ifndef __CRYPTO_CONTENTINFO_H__
#define __CRYPTO_CONTENTINFO_H__

#include "ObjectIdentifier.h"
#include "DerInputStream.h"
#include "DerValue.h"
#include <string>
#include <vector>

namespace tp{
    namespace crypto{
        class ContentInfo{
        public:
            ContentInfo(const ObjectIdentifier& contentType, const DerValue& content):
            m_contentType(contentType),
            m_content(content){
                m_contentType = contentType;
                m_content = content;
            }

            ContentInfo(const std::vector<uint8_t>& bytes){
                m_contentType = DATA_OID;
            }

            ContentInfo(DerInputStream& derin){
                ContentInfo(derin, false);
            }

            ContentInfo(DerInputStream& derin, bool oldStyle){
                DerInputStream* disType;
                DerInputStream* disTaggedContent;
                DerValue type;
                DerValue taggedContent;
                std::vector<DerValue> typeAndContent;
                std::vector<DerValue> contents;

                derin.getSequence(2, typeAndContent);
                type = typeAndContent[0];
                std::vector<uint8_t> out;
                type.toByteArray(out);
                disType = new DerInputStream(out);
                
            }

        public:

            DerValue getContent(){
                return m_content;
            }

            ObjectIdentifier getContentType(){
                return m_contentType;
            }


            std::vector<uint8_t> getData(){
                std::vector<uint8_t> out;
                if (m_contentType == DATA_OID || m_contentType == OLD_DATA_OID){

                }
                return out;
            }

            void encode(){

            }
            std::vector<uint8_t> getContentBytes(){
                // TODO
                std::vector<uint8_t> out;
                return out;
            }
            
            std::string toString(){
                // TODO
                std::string out = "";
                out = "Content Info Sequence\n\tContent type:";
                out += m_contentType.toString();
                out += "\n";
                out += "\tContent: ";
                out += m_content.toString();
                return out;
            }
        private:
            ObjectIdentifier m_contentType;
            DerValue m_content;

        public:
            static ObjectIdentifier PKCS7_OID;
            static ObjectIdentifier DATA_OID;
            static ObjectIdentifier SIGNED_DATA_OID;
            static ObjectIdentifier OLD_DATA_OID;
            static ObjectIdentifier OLD_SIGNED_DATA_OID;
        };
    }
}

#endif // end of __CRYPTO_CONTENTINFO_H__