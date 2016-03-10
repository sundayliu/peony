#ifndef __CRYPTO_BYTE_ARRAY_OUTPUT_STREAM_H__
#define __CRYPTO_BYTE_ARRAY_OUTPUT_STREAM_H__

#include "OutputStream.h"
#include <vector>
#include <inttypes.h>
#include <string>
namespace tp{
    namespace crypto{
        class OutputStream;
        class ByteArrayOutputStream :public OutputStream{
        public:
            ByteArrayOutputStream(){
                m_count = 0;
                m_buf.reserve(32);
            }

            ByteArrayOutputStream(int size){
                m_count = 0;
                if (size < 0){
                    size = 32;
                }
                m_buf.reserve(size);
            }

            void write(uint8_t byte){
                m_buf.push_back(byte);
                m_count += 1;
            }

            void write(const std::vector<uint8_t>& data, int off, int len){
                if ((off < 0) || (len < 0) || (off > data.size()) || ((off + len) > data.size())){
                    return;
                }
                for (int i = 0; i < len; i++){
                    m_buf.push_back(data[i + off]);
                }
                m_count += len;
            }

            void writeTo(OutputStream& out){
                out.write(m_buf, 0, m_count);
            }
            void reset(){ m_count = 0; }
            std::vector<uint8_t> toByteArray()const{ return m_buf; }
            int size() const{ return m_count; }
            std::string toString() const{
                std::string ret(m_count, '1');
                for (std::vector<uint8_t>::size_type i = 0; i < m_count; ++i){
                    ret[i] = m_buf[i];
                }
                return ret;
            }
            void close(){}
        protected:
            std::vector<uint8_t> m_buf;
            std::vector<uint8_t>::size_type m_count;

        };
    }
}

#endif