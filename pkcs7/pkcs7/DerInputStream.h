#ifndef __CRYPTO_DER_INPUTSTREAM_H__
#define __CRYPTO_DER_INPUTSTREAM_H__

#include "DerInputBuffer.h"
#include "DerValue.h"
#include <inttypes.h>


namespace tp{
namespace crypto{

    class DerInputBuffer;
    class DerInputStream{
    public:
        DerInputStream(){}
        DerInputStream(const uint8_t* data, size_t length);
        DerInputStream(const std::vector<uint8_t>& data);
        DerInputStream(const std::vector<uint8_t>& data, int offset, int len);
        DerInputStream(const DerInputBuffer& buf);
        DerInputStream(const DerInputStream& obj){

        }

        void operator=(const DerInputStream& obj){

        }
        ~DerInputStream(){
            if (m_buffer != NULL){
                delete m_buffer;
                m_buffer = NULL;
            }
        }

    public:
        bool  getSequence(int startLen, std::vector<DerValue>& out){
            if (m_buffer != NULL){
                m_tag = m_buffer->read();
                if (m_tag == DerValue::tag_Sequence){
                    //
                    return readVector(startLen, out);
                }
            }
            return false;
        }
        void reset() {
            if (m_buffer != NULL){
                m_buffer->reset();
            }
        }

        void mark(int value){
            if (m_buffer != NULL){
                m_buffer->mark(value);
            }
        }

        int available(){
            if (m_buffer != NULL){
                return m_buffer->available();
            }
            return 0;
        }

        DerInputStream* subStream(int len, bool do_skip);

    protected:
        bool readVector(int startLen, std::vector<DerValue>& out){
            if (m_buffer == NULL){
                return false;
            }

            uint8_t lenByte = m_buffer->read();
            int len = getLength((lenByte & 0xff), *m_buffer);
            if (len == -1){
                // indefinite length encoding
                return false;
            }

            if (len == 0){
                return false;
            }


            DerInputStream* newstr;
            if (m_buffer->available() == len){
                newstr = this;
            }
            else{
                newstr = subStream(len, true);
            }

            do{
                DerValue value(*(newstr->m_buffer));
                out.push_back(value);
                startLen--;
            } while (startLen > 0 && newstr->available() > 0);
            return true;
        }

    public:
        static int getLength(int lenByte, DerInputBuffer& input);

    private:
        void init(const std::vector<uint8_t>& data, int offset, int len);
        
    private:
        DerInputBuffer* m_buffer;
        uint8_t m_tag;
    };

}
}

#endif