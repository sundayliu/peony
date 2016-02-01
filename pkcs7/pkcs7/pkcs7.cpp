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
#include <map>
#include <string>


/*
1.2.840.113549.1.7.1 - data
1.2.840.113549.1.7.2 - signedData
1.2.840.113549.1.7.3 - envelopedData
1.2.840.113549.1.7.4 - signedAndEnvelopedData
1.2.840.113549.1.7.5 - digestedData
1.2.840.113549.1.7.6 - encryptedData
*/

std::map<std::string, std::string> OID_MAP = {
  { "1.2.840.113549.1.7.2", "pkcs7-signedData" },
  {"1.2.840.113549.1.7.1", "pkcs7-data"},
  {"1.3.14.3.2.26", "sha1"},
  { "1.2.840.113549.1.1.11", "sha256WithRSAEncryption" },
  {"2.5.4.6", "countryName" },
  { "2.5.4.8", "stateOrProvinceName" },
  { "2.5.4.7", "localityName" },
  { "2.5.4.10", "organizationName" },
  { "2.5.4.11", "organizationalUnitName" },
  { "2.5.4.3", "commonName" },
  { "1.2.840.113549.1.1.1", "RSA encryption" },
  {"2.5.29.14", "X509v3 Subject Key Identifier"}
};

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

// IA5 table
static const struct {
    int code, value;
} ia5_table[] = {
    { '\0', 0 },
    { '\a', 7 },
    { '\b', 8 },
    { '\t', 9 },
    { '\n', 10 },
    { '\f', 12 },
    { '\r', 13 },
    { ' ', 32 },
    { '!', 33 },
    { '"', 34 },
    { '#', 35 },
    { '$', 36 },
    { '%', 37 },
    { '&', 38 },
    { '\'', 39 },
    { '(', 40 },
    { ')', 41 },
    { '*', 42 },
    { '+', 43 },
    { ',', 44 },
    { '-', 45 },
    { '.', 46 },
    { '/', 47 },
    { '0', 48 },
    { '1', 49 },
    { '2', 50 },
    { '3', 51 },
    { '4', 52 },
    { '5', 53 },
    { '6', 54 },
    { '7', 55 },
    { '8', 56 },
    { '9', 57 },
    { ':', 58 },
    { ';', 59 },
    { '<', 60 },
    { '=', 61 },
    { '>', 62 },
    { '?', 63 },
    { '@', 64 },
    { 'A', 65 },
    { 'B', 66 },
    { 'C', 67 },
    { 'D', 68 },
    { 'E', 69 },
    { 'F', 70 },
    { 'G', 71 },
    { 'H', 72 },
    { 'I', 73 },
    { 'J', 74 },
    { 'K', 75 },
    { 'L', 76 },
    { 'M', 77 },
    { 'N', 78 },
    { 'O', 79 },
    { 'P', 80 },
    { 'Q', 81 },
    { 'R', 82 },
    { 'S', 83 },
    { 'T', 84 },
    { 'U', 85 },
    { 'V', 86 },
    { 'W', 87 },
    { 'X', 88 },
    { 'Y', 89 },
    { 'Z', 90 },
    { '[', 91 },
    { '\\', 92 },
    { ']', 93 },
    { '^', 94 },
    { '_', 95 },
    { '`', 96 },
    { 'a', 97 },
    { 'b', 98 },
    { 'c', 99 },
    { 'd', 100 },
    { 'e', 101 },
    { 'f', 102 },
    { 'g', 103 },
    { 'h', 104 },
    { 'i', 105 },
    { 'j', 106 },
    { 'k', 107 },
    { 'l', 108 },
    { 'm', 109 },
    { 'n', 110 },
    { 'o', 111 },
    { 'p', 112 },
    { 'q', 113 },
    { 'r', 114 },
    { 's', 115 },
    { 't', 116 },
    { 'u', 117 },
    { 'v', 118 },
    { 'w', 119 },
    { 'x', 120 },
    { 'y', 121 },
    { 'z', 122 },
    { '{', 123 },
    { '|', 124 },
    { '}', 125 },
    { '~', 126 }
};

static int der_ia5_char_encode(int c){
    int x;
    for (x = 0; x < (int)(sizeof(ia5_table) / sizeof(ia5_table[0])); x++) {
        if (ia5_table[x].code == c) {
            return ia5_table[x].value;
        }
    }
    return -1;
}

static int der_ia5_value_decode(int v){
    int x;
    for (x = 0; x < (int)(sizeof(ia5_table) / sizeof(ia5_table[0])); x++) {
        if (ia5_table[x].value == v) {
            return ia5_table[x].code;
        }
    }
    return -1;
}

static int char_to_int(unsigned char x)
{
    switch (x)  {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    }
    return 100;
}

typedef struct{
    uint32_t YY;
    uint32_t MM;
    uint32_t DD;
    uint32_t hh;
    uint32_t mm;
    uint32_t ss;
    uint32_t off_dir; // 0 == + 1 == -
    uint32_t off_hh;  // timezone offset hours
    uint32_t off_mm;
}tp_utctime;
    
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
    bool decodeUTCTime(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        printf("offset=%lu h=%lu l=%u:UTCTime\n", m_current_idx, header_length + 1, body_length);
        {
            // parse utc time
            uint8_t buf[32] = { 0 };
            tp_utctime utctime;
            for (uint32_t i = 0; i < body_length; i++){
                buf[i] = der_ia5_value_decode(in[header_length+1+i]);
            }

#define DECODE_V(y, max) \
    y = char_to_int(buf[i]) * 10 + char_to_int(buf[i+1]); \
    i += 2;

            // YYMMDDhhmmZ
            //YYMMDDhhmm + hh'mm'
            //    YYMMDDhhmm - hh'mm'
            //    YYMMDDhhmmssZ
            //    YYMMDDhhmmss + hh'mm'
            //    YYMMDDhhmmss - hh'mm'
            uint32_t i = 0;
            DECODE_V(utctime.YY, 100);
            DECODE_V(utctime.MM, 13);
            DECODE_V(utctime->DD, 32);
            DECODE_V(utctime.hh, 24);
            DECODE_V(utctime.mm, 60);
            if (buf[i] == 'Z'){
                // end
            }
            else if (buf[i] == '+' || buf[i] == '-'){
                utctime.off_dir = (buf[i++] == '+') ? 0 : 1;
                DECODE_V(utctime.off_hh, 24);
                DECODE_V(utctime.off_mm, 60);
            }
            else{
                DECODE_V(utctime.ss, 60);
                if (buf[i] == 'Z'){
                    // end;
                }
                else if (buf[i] == '+' || buf[i] == '-'){
                    utctime.off_dir = (buf[i++] == '+') ? 0 : 1;
                    DECODE_V(utctime.off_hh, 24);
                    DECODE_V(utctime.off_mm, 60);
                }
            }
        }

        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        return true;
    }
    bool decodePrintableString(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        
        
        printf("offset=%lu h=%lu l=%u:", m_current_idx, header_length + 1, body_length);
        for (uint32_t i = 0; i < body_length; i++){
            printf("%c", in[header_length + 1 + i]);
        }

        printf(":PRINTABLESTRING\n");


        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        return true;
    }

    bool decodeBitString(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        printf("offset=%lu h=%lu l=%u:BITSTRING\n", m_current_idx, header_length + 1, body_length);

        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        return true;
    }

    bool decodeOctetString(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        printf("offset=%lu h=%lu l=%u:OCTET STRING\n", m_current_idx, header_length + 1, body_length);

        uint32_t count = body_length / 16;
        uint32_t remain = body_length % 16;
        for (uint32_t i = 0; i < count; i++){
            printf("\t");
            for (uint32_t j = 0; j < 16; j++){
                printf("%02X ", in[header_length + 1 + 16 * i + j]);
            }
            printf("\n");
        }

        printf("\t");
        for (uint32_t j = 0; j < remain; j++){
            //printf("\t");
            printf("%02X ", in[header_length + 1 + count * 16 + j]);

        }
        printf("\n");

        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        return true;
    }


    bool decodeNULL(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        printf("offset=%lu h=%lu l=%u:NULL\n", m_current_idx, header_length + 1, body_length);

        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        return true;
    }
    bool decodeSequence(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        //printf("body|header:%d|%lu\n", body_length, header_length);
        
        printf("offset=%lu h=%lu l=%u:SEQUENCE\n", m_current_idx, header_length + 1, body_length);
        cur_idx += header_length;
        m_current_idx += header_length + 1;// + body_length; cons
        return true;
    }
    bool decodeSet(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        //printf("body|header:%d|%lu\n", body_length, header_length);
        printf("offset=%lu h=%lu l=%u:SET\n", m_current_idx, header_length + 1, body_length);
        cur_idx += header_length;
        m_current_idx += header_length + 1;// + body_length; cons
        return true;
    }
    bool decodeInteger(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        printf("offset=%lu h=%lu l=%u:INTEGER\n", m_current_idx, header_length + 1, body_length);
        
        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        
        
        return true;
    }
    bool decodeObjectIdentifier(const uint8_t* in, size_t inlen){
        uint32_t cur_idx = 1;
        uint32_t body_length = 0;
        size_t header_length = 0;
        body_length = decodeLength(in + cur_idx, inlen - cur_idx, header_length);
        printf("offset=%lu h=%lu l=%u:", m_current_idx, header_length + 1, body_length);
        
        unsigned y = 0;
        unsigned t = 0;
        cur_idx += header_length;
        m_current_idx += header_length + 1 + body_length;
        unsigned long* words = new unsigned long[body_length + 1];
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
        //printf("value:");
        std::string oid = "";
        for (i = 0; i < y; i++){
          char temp[32] = { 0 };
            printf("%lu", words[i]);
            oid += ltoa(words[i], temp, 10);
            if (i < y -1){
                printf(".");
                oid += ".";
            }
            else{
                std::map<std::string, std::string>::iterator it = OID_MAP.find(oid);
                if (it != OID_MAP.end()){
                    printf(":%s", it->second.c_str());
                }
                else{
                    printf(":Unknown");
                }
                printf(":OBJECT\n");
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
            //printf("INTEGER\n");
            decodeInteger(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
            //parse_fail = true;
            break;
        case ASN1_TAG_BITSTRING:
            //printf("BITSTRINE\n");
            //parse_fail = true;
            decodeBitString(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
            break;
        case ASN1_TAG_OCTESTRING:
            //printf("OCTESTRING\n");
            //parse_fail = true;
            decodeOctetString(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
            break;
        case ASN1_TAG_NULL:
            //printf("NULL\n");
            //parse_fail = true;
            decodeNULL(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
            break;
        case ASN1_TAG_OBJECTID:
            //printf("Object Identifier\n");
            decodeObjectIdentifier(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
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
            //printf("PRINTABLESTRING\n");
            //parse_fail = true;
            decodePrintableString(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
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
            //printf("UTCTIME\n");
            //parse_fail = true;
            decodeUTCTime(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
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
            //printf("SEQUENCE\n");
            decodeSequence(m_buffer+m_current_idx, m_buffer_size-m_current_idx);
            break;
        case ASN1_TAG_SET:
        //case ASN1_TAG_SETOF:
            //printf("SET\n");
            //parse_fail = true;
            decodeSet(m_buffer + m_current_idx, m_buffer_size - m_current_idx);
            break;
        default:
            if (isConstructed(m_tag)){
                body_length = decodeLength(m_buffer + m_current_idx + 1, m_buffer_size - m_current_idx - 1, header_length);
                //printf("constructed[%d]\n", m_tag & 0x20);
                //printf("body|header:%u|%lu\n", body_length, header_length);
                printf("offset=%lu h=%lu l=%u:cons\n", m_current_idx, header_length + 1, body_length);
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