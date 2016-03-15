#ifndef __CRYPTO_ALGORITHM_ID_H__
#define __CRYPTO_ALGORITHM_ID_H__

#include <vector>
#include <inttypes.h>
namespace tp{
    namespace crypto{
        class ObjectIdentifier;
        class DerValue;
        class AlgorithmParameters{

        };


        class AlgorithmId{
        public:
            AlgorithmId();
            AlgorithmId(const std::vector<uint8_t>& encoding);

        public:
            static AlgorithmId parse(DerValue& val);

        private:
            ObjectIdentifier* m_algid;
            AlgorithmParameters* m_algParams;
            std::vector<uint8_t> m_encoding;
        };
    }
}

#endif