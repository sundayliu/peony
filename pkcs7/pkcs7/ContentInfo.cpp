#include "ContentInfo.h"

#include <vector>

namespace tp{
    namespace crypto{
        static uint64_t _pkcs7[] = { 1, 2, 840, 113549, 1, 7 };
        static std::vector<uint64_t> pkcs7(_pkcs7, _pkcs7 + 6);

        static uint64_t _data[] = { 1, 2, 840, 113549, 1, 7, 1 };
        static std::vector<uint64_t> data(_data, _data + 7);

        static uint64_t _sdata[] = { 1, 2, 840, 113549, 1, 7, 2 };
        static std::vector<uint64_t> sdata(_sdata, _sdata + 7);

        static uint64_t _old_data[] = { 1, 2, 840, 1113549, 1, 7, 1 };
        static std::vector<uint64_t> old_data(_old_data, _old_data + 7);

        static uint64_t _old_sdata[] = { 1, 2, 840, 1113549, 1, 7, 2 };
        static std::vector<uint64_t> old_sdata(_old_sdata, _old_sdata + 7);

        ObjectIdentifier ContentInfo::PKCS7_OID(pkcs7);
        ObjectIdentifier ContentInfo::DATA_OID(data);
        ObjectIdentifier ContentInfo::OLD_DATA_OID(old_data);
        ObjectIdentifier ContentInfo::SIGNED_DATA_OID(sdata);
        ObjectIdentifier ContentInfo::OLD_SIGNED_DATA_OID(old_sdata);
    }
}