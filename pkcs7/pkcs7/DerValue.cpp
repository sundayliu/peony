#include "DerValue.h"
#include "DerInputStream.h"
#include "DerInputBuffer.h"
#include "DerOutputStream.h"

namespace tp{
    namespace crypto{
        uint8_t DerValue::TAG_UNIVERSAL = 0x000;
        uint8_t DerValue::TAG_APPLICATION = 0x040;
        uint8_t DerValue::TAG_CONTEXT = 0x080;
        uint8_t DerValue::TAG_PRIVATE = 0x0c0;

        uint8_t DerValue::tag_Boolean = 0x01;
        uint8_t DerValue::tag_Integer = 0x02;
        uint8_t DerValue::tag_BitString = 0x03;
        uint8_t DerValue::tag_OctetString = 0x04;
        uint8_t DerValue::tag_Null = 0x05;
        uint8_t DerValue::tag_ObjectId = 0x06;
        uint8_t DerValue::tag_Enumerated = 0x0A;
        uint8_t DerValue::tag_UTF8String = 0x0C;
        uint8_t DerValue::tag_PrintableString = 0x13;
        uint8_t DerValue::tag_T61String = 0x14;
        uint8_t DerValue::tag_IA5String = 0x16;
        uint8_t DerValue::tag_UTCTime = 0x17;
        uint8_t DerValue::tag_GeneralizedTime = 0x18;
        uint8_t DerValue::tag_GeneralizedString = 0x1B;
        uint8_t DerValue::tag_UniveralString = 0x1C;
        uint8_t DerValue::tag_BMPString = 0x1E;
        uint8_t DerValue::tag_Sequence = 0x30;
        uint8_t DerValue::tag_SequenceOf = 0x30;
        uint8_t DerValue::tag_Set = 0x31;
        uint8_t DerValue::tag_SetOf = 0x31;

        //////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////
        DerValue::DerValue(DerInputBuffer& input){
            m_tag = input.read();
            uint8_t lenByte = input.read();
            m_length = DerInputStream::getLength((lenByte & 0xff), input);
            if (m_length == -1){

            }
            else{
                DerInputBuffer temp = input.dup();
                temp.truncate(m_length);
                m_data = new DerInputStream(temp);
                temp.skip(m_length);
                m_buffer = new DerInputBuffer(temp);

                input.skip(m_length);
            }
        }

        bool DerValue::toByteArray(std::vector<uint8_t>& out){
            DerOutputStream os;
            encode(os);
            m_data->reset();
            out = os.toByteArray();
            return true;
        }

        bool DerValue::encode(DerOutputStream& out){
            out.write(m_tag);
            out.putLength(m_length);
            if (m_length > 0){
                m_buffer->reset();
                std::vector<uint8_t> value;

                if (m_buffer->read(value, m_length) == m_length){
                    out.write(value, 0, m_length);
                }

            }
            return true;
        }

        DerValue::DerValue(const DerValue& other){
            m_tag = other.m_tag;
            m_length = other.m_length;
            m_buffer = new DerInputBuffer(*(other.m_buffer));
            m_data = new DerInputStream(*(other.m_data));

        }

        void DerValue::operator=(const DerValue& other){
            if (this != &other){
                m_tag = other.m_tag;
                m_length = other.m_length;
                if (m_data != NULL){
                    delete m_data;
                    m_data = NULL;
                }
                if (other.m_data != NULL){
                    m_data = new DerInputStream(*(other.m_data));
                }
                else{
                    m_data = NULL;
                }
                
                if (m_buffer != NULL){
                    delete m_buffer;
                    m_buffer = NULL;
                }

                if (other.m_buffer != NULL){
                    m_buffer = new DerInputBuffer(*(other.m_buffer));
                }
                
            }
        }

        bool DerValue::toDerInputStream(DerInputStream& out){
            if (m_tag == tag_Sequence || m_tag == tag_Set){
                out = *m_data;
                return true;
            }
            return false;
        }
    }
}