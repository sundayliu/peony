#include "DerInputBuffer.h"

namespace tp{
namespace crypto{

DerInputBuffer::DerInputBuffer(const uint8_t* buf, size_t length):
    m_mark(0),
    m_pos(0){

    m_buf.clear();
    m_pos = 0;
    if (buf != NULL && length > 0){
        for (size_t i = 0; i < length; i++){
            m_buf.push_back(buf[i]);
        }
    }
}

}
}