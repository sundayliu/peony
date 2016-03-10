#ifndef __CRYPTO_OBJECT_IDENTIFIER_H__
#define __CRYPTO_OBJECT_IDENTIFIER_H__

#include <vector>
#include <string>
#include <inttypes.h>

#include "TPException.h"

#define snprintf sprintf_s

namespace tp{
    namespace crypto{
        class ObjectIdentifier{
        public:
            ObjectIdentifier(){

            }
            ObjectIdentifier(const std::vector<int>& values);
            ObjectIdentifier(const ObjectIdentifier& obj){
                m_stringForm = obj.m_stringForm;
                m_encoding = obj.m_encoding;
                m_values = m_values;
            }

            void operator=(const ObjectIdentifier& obj){
                if (this != &obj){
                    m_stringForm = obj.m_stringForm;
                    m_encoding = m_encoding;
                    m_values = m_values;
                }
            }

        public:
            bool operator == (const ObjectIdentifier& obj){
                if (m_values == obj.m_values){
                    return true;
                }
                else{
                    return false;
                }
            }

        public:
            std::string toString(){
                std::string out = "";
                for (std::vector<int>::size_type i = 0; i < m_values.size(); i++){
                    char temp[16] = { 0 };
                    snprintf(temp, sizeof(temp), "%d", m_values[i]);
                    out += temp;
                    if (i != m_values.size() - 1){
                        out += ".";
                    }
                }
                return out;
            }

        private:
            void init(const std::vector<int>& values);

        private:

            static int pack7Oid(int input, std::vector<uint8_t>& out, int* ooffset){
                std::vector<uint8_t> b;
                b.push_back((uint8_t)(input >> 24));
                b.push_back((uint8_t)(input >> 16));
                b.push_back((uint8_t)(input >> 8));
                b.push_back((uint8_t)(input));
                return 0;
            }

            static std::vector<uint8_t> pack(const std::vector<uint8_t>& in, int ioffset, int ilength, int iw, int ow){
                if (iw == ow){
                    return in;
                }

                std::vector<uint8_t> out;
                return out;
            }

            static int pack7Oid(const std::vector<uint8_t>& in, int ioffset, int ilength, std::vector<uint8_t>& out, int* ooffset){
                return 0;
            }
            static void checkCount(int count){
                if (count < 2){
                    throw TPException("ObjectIdentifier() -- Must be at least two oid component");
                }
            }

            static void checkFirstComponent(int first){
                if (first < 0 || first > 2){
                    throw TPException("ObjectIdentifier() -- First oid component is invalid");
                }
            }

            static void checkSecondComponent(int first, int second){
                if (second < 0 || first != 2 && second > 39){
                    throw TPException("ObjectIdentifier() -- Second oid component is invalid");
                }
            }

            static void checkOtherComponent(int i, int num){
                if (num < 0){
                    std::string message = "ObjectIdentifier() -- oid component #";
                    message +=  (i + 1) + " must be non-negative ";
                    throw TPException(message.c_str());

                }
            }

        private:
            std::vector<uint8_t> m_encoding;
            std::vector<int> m_values;
            std::string m_stringForm;
        };
    }
}

#endif