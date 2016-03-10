#include "DerInputBuffer.h"

namespace tp{
namespace crypto{

    DerInputBuffer::DerInputBuffer():
    m_pos(0),
    m_mark(0),
    m_count(0){
        m_buf.clear();
    }
DerInputBuffer::DerInputBuffer(const uint8_t* buf, size_t length):
    m_mark(0),
    m_pos(0),
    m_count(0){

    m_buf.clear();
    if (buf != NULL && length > 0){
        for (size_t i = 0; i < length; i++){
            m_buf.push_back(buf[i]);
        }
        m_count = m_buf.size();
    }
}

DerInputBuffer::DerInputBuffer(const std::vector<uint8_t>& data){
    m_buf = data;
    m_pos = 0;
    m_mark = 0;
    m_count = data.size();
}

DerInputBuffer::DerInputBuffer(const std::vector<uint8_t>& data, int offset, int len){
    m_buf = data;
    m_pos = offset;
    m_mark = offset;
    m_count = (offset + len > data.size()) ? data.size() : (offset + len);
}

DerInputBuffer::DerInputBuffer(const DerInputBuffer& other){
    m_buf = other.m_buf;
    m_pos = other.m_pos;
    m_mark = other.m_mark;
    m_count = other.m_count;
}

void DerInputBuffer::operator=(const DerInputBuffer& other){
    if (this != &other){
        m_buf = other.m_buf;
        m_pos = other.m_pos;
        m_mark = other.m_mark;
        m_count = other.m_count;
    }
}

DerInputBuffer DerInputBuffer::dup(){
    DerInputBuffer retval(*this);
    retval.mark(0x7fffffff);
    return retval;
}

bool DerInputBuffer::toByteArray(std::vector<uint8_t>& out){
    int length = available();
    if (length <= 0){
        return false;
    }

    out.clear();
    for (int i = 0; i < length; i++){
        out.push_back(m_buf[i + m_pos]);
    }
    return true;
}

bool DerInputBuffer::operator==(const DerInputBuffer& other){
    if (this == &other){
        return true;
    }

    int length = this->available();
    if (length != other.available()){
        return false;
    }

    for (int i = 0; i < length; ++i){
        if (m_buf[m_pos + i] != other.m_buf[other.m_pos + i]){
            return false;
        }
    }
    return true;
}

}
}