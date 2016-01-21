//////////////////////////////////////////////////////////////////////////////////////////////////
// @file: crypto/pkcs/pkcs7.cpp
// @author: sundayliu
// @date: 2016.01.17
//////////////////////////////////////////////////////////////////////////////////////////////////
#include "pkcs7.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


/*
1.2.840.113549.1.7.1 - data
1.2.840.113549.1.7.2 - signedData
1.2.840.113549.1.7.3 - envelopedData
1.2.840.113549.1.7.4 - signedAndEnvelopedData
1.2.840.113549.1.7.5 - digestedData
1.2.840.113549.1.7.6 - encryptedData
*/

namespace tp{
namespace crypto{

#define ASN1_TAG_CLASS_UNIVERSAL 0x000     // UNIVERSAL的Tag是ASN.1标准定义的，给每一种内建类型定义一个固定tag值
#define ASN1_TAG_CLASS_APPLICATION 0x040   // APPLICATION的Tag，唯一标志应用内的一个类型,但是因为使用IMPORTS等方式下，很难保证唯一性，所以这种Tag类已经不推荐使用了 Order-number ::= [APPLICATION 0] NumericString
#define ASN1_TAG_CLASS_CONTEXT 0x080
#define ASN1_TAG_CLASS_PRIVATE 0x0C0

// ASN.1 tag macro define
#define ASN1_TAG_BOOLEAN                0x01
#define ASN1_TAG_INTEGER                0x02
#define ASN1_TAG_BITSTRING              0x03
#define ASN1_TAG_OCTESTRING             0x04
#define ASN1_TAG_NULL                   0x05
#define ASN1_TAG_OBJECTID               0x06
#define ASN1_TAG_ENUMERATED             0x0A
#define ASN1_TAG_UTF8STRING             0x0C
#define ASN1_TAG_PRINTABLESTRING        0x13
#define ASN1_TAG_T61STRING              0x14 // teletype string
#define ASN1_TAG_IA5STRING              0x16 // ASCII string
#define ASN1_TAG_UTCTIME                0x17   // UTC Time
#define ASN1_TAG_GENERALIZEDTIME        0x18 
#define ASN1_TAG_GENERALSTRING          0x1B
#define ASN1_TAG_UNIVERALSTRING         0x1C
#define ASN1_TAG_BMPSTRING              0x1E
#define ASN1_TAG_SEQUENCE               0x30
#define ASN1_TAG_SEQUENCEOF             0x30
#define ASN1_TAG_SET                    0x31
#define ASN1_TAG_SETOF                  0x31

    
class DerValue{
public:
    DerValue(const uint8_t* data, size_t len);
    ~DerValue();
    
    bool decode();
    bool encode();
    
    uint8_t getTag(){return m_tag;}
    uint32_t getLength(){return m_length;}
    
public:
    bool isConstructed(uint8_t tag){
        return ((tag & 0x20) == 0x20);
    }
    
    bool isContextSpecific(uint8_t tag){
        return ((tag & 0x0c0) == 0x080);
    }
    
public:
    static bool encodeLength(int value, uint8_t* outdata, size_t& outlen);
    static uint32_t decodeLength(const uint8_t* data, size_t len, size_t& outlen);
    
private:
    bool decodeBoolean(const uint8_t* in, size_t inlen, bool& out, uint32_t& outlen);
    bool decodeSequence(const uint8_t* in, size_t inlen, uint32_t& outlen);
    bool decodeObjectIdentifier(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        printf("body|header:%d|%lu\n", body_length, header_length);
        
        unsigned y = 0;
        unsigned t = 0;
        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        unsigned long* words = new unsigned long[body_length];
        while(body_length--){
            t = (t << 7) | (in[cur_idx] & 0x7F);
            if (!(in[cur_idx++] & 0x80)){
                // <= 0x7F
                if (y == 0){
                    words[0] = t / 40;
                    words[1] = t % 40;
                    y = 2;
                }
                else{
                    words[y++] = t;
                }
                t = 0;
            }
            else{
                // continue;
            }
        }
        
        unsigned i = 0;
        printf("value:");
        for (i = 0; i < y; i++){
            printf("%lu", words[i]);
            if (i < y -1){
                printf(".");
            }
            else{
                printf("\n");
            }
        }
        
        delete[] words;
        return true;
    }
    
private:
    uint8_t m_tag;
    uint32_t m_length;
    uint8_t* m_buffer;
    size_t m_buffer_size;
    size_t m_current_idx;
    
};

DerValue::DerValue(const uint8_t* data, size_t len):
    m_tag(0),
    m_length(-1),
    m_buffer(NULL),
    m_buffer_size(0){
    if (data == NULL || len <= 0){
        return;
    }
    
    m_buffer = new uint8_t[len];
    if (m_buffer != NULL){
        memcpy(m_buffer, data, len);
        m_buffer_size = len;
    }
}

DerValue::~DerValue(){
    if (m_buffer != NULL){
        delete[] m_buffer;
        m_buffer = NULL;
    }
}

bool DerValue::decodeBoolean(const uint8_t* in, size_t inlen, bool& out, uint32_t& outlen){
    return true;
}

bool DerValue::decodeSequence(const uint8_t* in, size_t inlen, uint32_t& outlen){
    //size_t header_length = 0;
    //uint32_t body_length = decodeLength(in, inlen, header_length);
    return true;
}

bool DerValue::decode(){
    if (m_buffer == NULL || m_buffer_size <= 0){
        return false;
    }
    
    m_current_idx = 0;
    bool parse_fail = false;
    while(m_current_idx < m_buffer_size){
        m_tag = m_buffer[m_current_idx];
        size_t header_length = 0;
        uint32_t body_length = 0;
        switch(m_tag){
        case ASN1_TAG_BOOLEAN:
            printf("BOOLEAN\n");
            parse_fail = true;
            break;
        case ASN1_TAG_INTEGER:
            printf("INTEGER\n");
            parse_fail = true;
            break;
        case ASN1_TAG_BITSTRING:
            printf("BITSTRINE\n");
            parse_fail = true;
            break;
        case ASN1_TAG_OCTESTRING:
            printf("OCTESTRING\n");
            parse_fail = true;
            break;
        case ASN1_TAG_NULL:
            printf("NULL\n");
            parse_fail = true;
            break;
        case ASN1_TAG_OBJECTID:
            printf("Object Identifier\n");
            decodeObjectIdentifier(m_buffer + m_current_idx, m_buffer_size - m_buffer_size);
            break;
        case ASN1_TAG_ENUMERATED:
            printf("ENUMERATED\n");
            parse_fail = true;
            break;
        case ASN1_TAG_UTF8STRING:
            printf("UTF8STRING\n");
            parse_fail = true;
            break;
        case ASN1_TAG_PRINTABLESTRING:
            printf("PRINTABLESTRING\n");
            parse_fail = true;
            break;
        case ASN1_TAG_T61STRING:
            printf("T61STRING\n");
            parse_fail = true;
            break;
        case ASN1_TAG_IA5STRING:
            printf("IA5STRING\n");
            parse_fail = true;
            break;
        case ASN1_TAG_UTCTIME:
            printf("UTCTIME\n");
            parse_fail = true;
            break;
        case ASN1_TAG_GENERALIZEDTIME:
            printf("GENERALIZEDTIME\n");
            parse_fail = true;
            break;
        case ASN1_TAG_UNIVERALSTRING:
            printf("UNIVERSALSTRING\n");
            parse_fail = true;
            break;
        case ASN1_TAG_BMPSTRING:
            printf("BMPSTRING\n");
            parse_fail = true;
            break;
        case ASN1_TAG_SEQUENCE:
        //case ASN1_TAG_SEQUENCEOF:
            printf("SEQUENCE\n");
            body_length = decodeLength(m_buffer + m_current_idx + 1, m_buffer_size - m_current_idx - 1, header_length);
            printf("body|header:%u|%lu\n", body_length, header_length + 1);
            m_current_idx += header_length + 1;
            break;
        case ASN1_TAG_SET:
        //case ASN1_TAG_SETOF:
            printf("SET\n");
            parse_fail = true;
            break;
        default:
            if (isConstructed(m_tag)){
                body_length = decodeLength(m_buffer + m_current_idx + 1, m_buffer_size - m_current_idx - 1, header_length);
                printf("constructed[%d]\n", m_tag & 0x20);
                printf("body|header:%u|%lu\n", body_length, header_length);
                m_current_idx += header_length + 1;
            }
            else{
                printf("!error, Not recognize tag:%d\n", m_tag);
                parse_fail = true;
            }
            
            break;
        }
        
        if (parse_fail){
            break;
        }
    }
    
    return true;
}
    

uint32_t DerValue::decodeLength(const uint8_t* data, size_t len, size_t& outlen){
    if (data == NULL || len <= 0){
        return -1;
    }
    
    int value = 0;
    int tmp = 0;
    size_t cur_idx = 0;
    tmp = data[cur_idx++];
    if ((tmp & 0x80) == 0x00){
        value = tmp; // 1 byte
    }
    else{
        tmp &=0x7f;
        if (tmp <= 0 || tmp > 4){
            // 0 indicates indefinite length
            // > 4 more than 4Gb of data
            return -1;
        }
        
        while(tmp > 0){
            if (cur_idx >= len){
                value = -1;
                break;
            }
            value <<= 8;
            value += 0x0ff & data[cur_idx++];
            tmp--;
        }
    }
    
    
    outlen = cur_idx;
    return value;
}

///
/// PKCS7
///
    
PKCS7::PKCS7(const std::string& filename):
    m_data(NULL),
    m_data_size(0),
    m_valid(false),
    m_filename(filename){
    FILE* fp = fopen(m_filename.c_str(), "rb");
    if (fp != NULL){
        fseek(fp, 0, SEEK_END);
        size_t filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (filesize > 0){
            m_data = new uint8_t[filesize];
            if (m_data != NULL){
                m_data_size = fread(m_data, 1, filesize, fp);
                if (m_data_size == filesize){
                    m_valid = parse();
                }
                else{
                    m_data_size = 0;
                }
            }
        }
        fclose(fp);
    }
    else{
        printf("fopen fail error:%s\n", strerror(errno));
    }
}

PKCS7::PKCS7(const uint8_t* data, size_t len):
    m_data(NULL),
    m_data_size(0),
    m_valid(false),
    m_filename("")
{
    if (data == NULL || len <= 0){
        return;
    }
    
    m_data = new uint8_t[len];
    if (m_data != NULL){
        memcpy(m_data, data, len);
        m_data_size = len;
        m_valid = parse();
    }
}

bool PKCS7::parse(){
    if (m_data == NULL || m_data_size <= 0){
        return false;
    }
    
    printf("pkcs7 data size:%lu\n", m_data_size);
    
    DerValue der_value(m_data, m_data_size);
    der_value.decode();
    
    return true;
}

PKCS7::~PKCS7(){
    if (m_data != NULL){
        delete[] m_data;
        m_data = NULL;
    }
}
    
}
}