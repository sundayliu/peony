#include "BigInteger.h"

namespace tp{
    namespace crypto{
        BigInteger::BigInteger(){
            m_val.clear();
        }
        BigInteger::BigInteger(const uint8_t* val, int len){
            m_val.clear();
            if (val != NULL && len > 0){
                for (int i = 0; i < len; i++){
                    m_val.push_back(val[i]);
                }
                
            }
        }

        BigInteger::BigInteger(const std::vector<uint8_t>& val){
            m_val = val;
        }

        BigInteger::BigInteger(const BigInteger& other){
            m_val = other.m_val;
        }

        void BigInteger::operator=(const BigInteger& other){
            if (this != &other){
                m_val = other.m_val;
            }
        }

        std::vector<uint8_t> BigInteger::getValue() const{
            return m_val;
        }
    }
}