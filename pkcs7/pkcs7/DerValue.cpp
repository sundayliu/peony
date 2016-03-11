#include "DerValue.h"
#include "DerInputStream.h"
#include "DerInputBuffer.h"

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
            }
        }

        bool DerValue::toByteArray(std::vector<uint8_t>& out){
            return true;
        }
    }
}