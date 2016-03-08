#ifndef __CRYPTO_DER_INPUTSTREAM_H__
#define __CRYPTO_DER_INPUTSTREAM_H__

#include "DerInputBuffer.h"
#include <inttypes.h>

namespace tp{
namespace crypto{

    class DerInputStream{
    public:
        DerInputStream(uint8_t* data, size_t length);
        ~DerInputStream(){
            if (m_buffer != NULL){
                delete m_buffer;
                m_buffer = NULL;
            }
        }

    public:
        void reset() {
            if (m_buffer != NULL){
                m_buffer->reset();
            }
        }

        void mark(int value){
            if (m_buffer != NULL){
                m_buffer->mark();
            }
        }

    public:
        uint8_t m_tag;
    private:
        DerInputBuffer* m_buffer;
    };

}
}

#endif