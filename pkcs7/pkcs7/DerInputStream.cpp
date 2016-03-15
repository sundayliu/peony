#include "DerInputStream.h"
#include <limits.h>
#include "ObjectIdentifier.h"
#include "BigInteger.h"
#include "DerValue.h"

namespace tp{
    namespace crypto{
        DerInputStream::DerInputStream(const uint8_t* data, size_t length) :
            m_tag(0),
            m_buffer(NULL){
            if (data != NULL && length >= 2){
                m_buffer = new DerInputBuffer(data, length);
            }
        }

        DerInputStream::DerInputStream(const std::vector<uint8_t>& data){
            init(data, 0, data.size());
        }

        DerInputStream::DerInputStream(const std::vector<uint8_t>& data, int offset, int len){
            init(data, offset, len);
        }


        DerInputStream::DerInputStream(const DerInputBuffer& buf){
            m_buffer = new DerInputBuffer(buf);
            m_buffer->mark(INT_MAX);
        }

        DerInputStream* DerInputStream::subStream(int len, bool do_skip){
            DerInputBuffer newbuf = *m_buffer;
            newbuf.truncate(len);
            if (do_skip){
                m_buffer->skip(len);
            }
            return new DerInputStream(newbuf);
        }

        int DerInputStream::getLength(int lenByte, DerInputBuffer& input){
            int value = 0;
            int temp = 0;

            temp = lenByte;
            if ((temp & 0x080) == 0x00){  // short form, 1byte 
                value = temp;
            }
            else{
                temp &= 0x07f;            // long form or indefinite
                // temp == 0 indicates indefinite length encoded data
                // temp > 4 indicates more than 4Gb of data
                if (temp == 0){
                    return -1;
                }
                
                if (temp < 0 || temp > 4){
                    return -1;
                }

                for (value = 0; temp > 0; temp--){
                    value <<= 8;
                    value += 0x0ff & (input.read());
                }
            }

            return value;
        }

        void DerInputStream::init(const std::vector<uint8_t>& data, int offset, int len){
            m_buffer = new DerInputBuffer(data, offset, len);
        }

        ObjectIdentifier DerInputStream::getOID(){
            return ObjectIdentifier(*this);
        }

        BigInteger DerInputStream::getBigInteger(){
            BigInteger result;
            if (m_buffer->read() == DerValue::tag_Integer){
                int len = getLength();
                std::vector<uint8_t> tmp;
                for (int i = 0; i < len; i++){
                    tmp.push_back(m_buffer->read());
                }

                result = BigInteger(tmp);
            }
            return result;
        }

        DerValue DerInputStream::getDerValue(){
            return DerValue(*m_buffer);
        }

        bool DerInputStream::getOctetString(std::vector<uint8_t>& out){
            if (m_buffer->read() != DerValue::tag_OctetString){
                return false;
            }

            int length = getLength();
            if ((length != 0) && (m_buffer->read(out, length) != length)){
                return false;
            }
            return true;
        }

        bool DerInputStream::getSet(int startLen, bool implicit, std::vector<DerValue>& out){
            m_tag = m_buffer->read();
            if (!implicit){
                if (m_tag != DerValue::tag_Set){
                    return false;
                }
            }
            return readVector(startLen, out);
        }

        bool DerInputStream::getSet(int startLen, std::vector<DerValue>& out){
            m_tag = m_buffer->read();
            if (m_tag != DerValue::tag_Set){
                return false;
            }
            return readVector(startLen, out);
        }

        DerInputStream::DerInputStream(const DerInputStream& other){
            m_tag = other.m_tag;
            m_buffer = new DerInputBuffer(*(other.m_buffer));
        }

        void DerInputStream::operator=(const DerInputStream& other){
            if (this != &other){
                m_tag = other.m_tag;
                if (m_buffer != NULL){
                    delete m_buffer;
                }

                m_buffer = new DerInputBuffer(*(other.m_buffer));
            }
        }
    }
}