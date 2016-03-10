#ifndef __CRYPTO_OUTPUT_STREAM_H__
#define __CRYPTO_OUTPUT_STREAM_H__

#include <inttypes.h>
#include <vector>

namespace tp{
    namespace crypto{
        class OutputStream{
        public:
            virtual void write(uint8_t byte) = 0;
            virtual void write(const std::vector<uint8_t>& data){
                write(data, 0, data.size());
            }
            virtual void write(const std::vector<uint8_t>& data, int off, int len){
                if ((len == 0) || (off < 0) || (off > data.size()) || (len < 0) || ((off + len) > data.size())){
                    return;
                }
                for (int i = 0; i < len; i++){
                    write(data[off + i]);
                }
            }
            virtual void flush(){}
            virtual void close(){}
        };
    }
}

#endif