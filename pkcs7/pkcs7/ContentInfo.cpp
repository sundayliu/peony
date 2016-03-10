#include "ContentInfo.h"

#include <vector>

namespace tp{
    namespace crypto{
        static int _pkcs7[] = { 1, 2, 840, 113549, 1, 7 };
        static std::vector<int> pkcs7(_pkcs7, _pkcs7 + 6);

        static int _data[] = {1,2,840,113549,1,7,1};
        static std::vector<int> data(_data, _data + 7);

        static int _sdata[] = { 1, 2, 840, 113549, 1, 7, 2 };
        static std::vector<int> sdata(_sdata, _sdata + 7);

        static int _old_data[] = { 1, 2, 840, 1113549, 1, 7, 1 };
        static std::vector<int> old_data(_old_data, _old_data + 7);

        static int _old_sdata[] = { 1, 2, 840, 1113549, 1, 7, 2 };
        static std::vector<int> old_sdata(_old_sdata, _old_sdata + 7);

        ObjectIdentifier ContentInfo::PKCS7_OID(pkcs7);
        ObjectIdentifier ContentInfo::DATA_OID(data);
        ObjectIdentifier ContentInfo::OLD_DATA_OID(old_data);
        ObjectIdentifier ContentInfo::SIGNED_DATA_OID(sdata);
        ObjectIdentifier ContentInfo::OLD_SIGNED_DATA_OID(old_sdata);
    }
}