#include "DerInputStream.h"

namespace tp{
    namespace crypto{
        DerInputStream::DerInputStream(uint8_t* data, size_t length) :
            m_tag(0),
            m_buffer(NULL){
            if (data != NULL && length >= 2){
                m_buffer = new DerInputBuffer(data, length);
            }
        }
    }
}