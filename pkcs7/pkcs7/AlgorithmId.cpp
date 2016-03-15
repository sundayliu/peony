#include "AlgorithmId.h"
#include "DerValue.h"

#include "ObjectIdentifier.h"
#include "DerInputStream.h"
namespace tp{
    namespace crypto{
        AlgorithmId::AlgorithmId(){
            m_encoding.clear();
        }

        AlgorithmId::AlgorithmId(const std::vector<uint8_t>& encoding){
            m_encoding = encoding;
        }

        AlgorithmId AlgorithmId::parse(DerValue& val){
            if (val.getTag() == DerValue::tag_Sequence){
                ObjectIdentifier algid;
                DerValue params;
                DerInputStream dis;
                val.toDerInputStream(dis);

                algid = dis.getOID();
                if (dis.available() == 0){

                }
                else{
                    params = dis.getDerValue();
                    if (params.getTag() == DerValue::tag_Null){
                        if (params.getLength() != 0){
                            // error

                        }
                    }
                }
            }
            return AlgorithmId();
        }
    }
}