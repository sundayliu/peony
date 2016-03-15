#include "ObjectIdentifier.h"
#include "DerInputStream.h"

namespace tp{
    namespace crypto{
        ObjectIdentifier::ObjectIdentifier(const std::vector<uint64_t>& values){
            checkCount(values.size());
            checkFirstComponent(values[0]);
            checkSecondComponent(values[0], values[1]);
            for (std::vector<int>::size_type i = 2; i < values.size(); i++){
                checkOtherComponent(i, values[i]);
            }

            m_values = values;
            init(values);
        }

        void ObjectIdentifier::init(const std::vector<uint64_t>& values){

        }

        ObjectIdentifier::ObjectIdentifier(DerInputStream& derin){
            uint8_t type_id;

            type_id = derin.getByte();
            if (type_id != DerValue::tag_ObjectId){
                // ERROR;
                return;
            }

            int len = derin.getLength();
            m_encoding.reserve(len);
            derin.getBytes(m_encoding, len);
            check(m_encoding);
            decode();
        }

        void ObjectIdentifier::check(const std::vector<uint8_t>& encoding){

        }

        void ObjectIdentifier::decode(){
            uint64_t temp = 0;
            std::vector<uint8_t>::size_type i;
            int start = 0;
            for (i = 0; i < m_encoding.size(); i++){
                temp = (temp << 7) | (m_encoding[i] & 0x7F);
                if ((m_encoding[i] & 0x80) == 0){
                    if (start == 0){
                        m_values.push_back(temp / 40);
                        m_values.push_back(temp % 40);
                        start = 2;
                    }
                    else{
                        m_values.push_back(temp);
                    }
                    temp = 0;
                }
            }
        }
    }
}