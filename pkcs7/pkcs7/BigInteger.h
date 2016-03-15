#ifndef __CRYPTO_BIG_INTEGER_H__
#define __CRYPTO_BIG_INTEGER_H__

#include <inttypes.h>
#include <vector>
namespace tp{
    namespace crypto{
        class BigInteger{
        public:
            BigInteger();
            BigInteger(const uint8_t* val, int len);
            BigInteger(const std::vector<uint8_t>& val);
            BigInteger(const BigInteger& other);
            void operator=(const BigInteger& other);

        public:
            std::vector<uint8_t> getValue() const;

        private:
            std::vector<uint8_t> m_val;
        };
    }
}

#endif 