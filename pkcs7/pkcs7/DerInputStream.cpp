#include "DerInputStream.h"
#include <limits.h>

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

        }
    }
}