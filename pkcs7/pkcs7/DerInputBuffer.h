#ifndef __CRYPTO_DER_INPUT_BUFFER_H__
#define __CRYPTO_DER_INPUT_BUFFER_H__

#include <vector>
#include <inttypes.h>


namespace tp{
namespace crypto{

    class ByteArrayInputStream;
class DerInputBuffer{
public:
    DerInputBuffer();
    DerInputBuffer(const uint8_t* buf, size_t length);
    DerInputBuffer(const std::vector<uint8_t>& data);
    DerInputBuffer(const std::vector<uint8_t>& data, int offset, int len);
    DerInputBuffer(const DerInputBuffer& other);
    void operator=(const DerInputBuffer& other);

public:
    DerInputBuffer dup();
    bool toByteArray(std::vector<uint8_t>& out);
    bool operator==(const DerInputBuffer& other);

public:

    long skip(long n){
        long k = m_count - m_pos;
        if (n < k){
            k = n < 0 ? 0 : n;
        }
        m_pos += k;
        return k;
    }
    void truncate(int len){
        if (len > available()){
            return;
        }
        m_count = m_pos + len;
    }
    bool peek(int* out){
        if (m_pos >= m_count){
            return false;
        }

        *out = m_buf[m_pos];
        return true;
    }
    void reset(){ m_pos = m_mark; }
    void mark(int readAheadLimit){ m_mark = m_pos; }

    int read(){
        if (m_pos < m_count){
            return m_buf[m_pos++] & 0xff;
        }
        else{
            return -1;
        }
    }

    int available()const{
        return m_count - m_pos;
    }

private:
    std::vector<uint8_t> m_buf;
    std::vector<uint8_t>::size_type m_pos;
    std::vector<uint8_t>::size_type m_mark;
    std::vector<uint8_t>::size_type m_count;
};


}
}

#endif