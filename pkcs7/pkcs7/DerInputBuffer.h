#ifndef __CRYPTO_DER_INPUT_BUFFER_H__
#define __CRYPTO_DER_INPUT_BUFFER_H__

#include <vector>
#include <inttypes.h>


namespace tp{
namespace crypto{

class DerInputBuffer{
public:
    DerInputBuffer(const uint8_t* buf, size_t length);

public:
    void reset(){ m_pos = m_mark; }
    void mark(){ m_mark = m_pos; }

private:
    std::vector<uint8_t> m_buf;
    std::vector<uint8_t>::size_type m_pos;
    std::vector<uint8_t>::size_type m_mark;
};


}
}

#endif