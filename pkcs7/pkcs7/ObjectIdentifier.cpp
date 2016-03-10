#include "ObjectIdentifier.h"

namespace tp{
    namespace crypto{
        ObjectIdentifier::ObjectIdentifier(const std::vector<int>& values){
            checkCount(values.size());
            checkFirstComponent(values[0]);
            checkSecondComponent(values[0], values[1]);
            for (std::vector<int>::size_type i = 2; i < values.size(); i++){
                checkOtherComponent(i, values[i]);
            }

            m_values = values;
            init(values);
        }

        void ObjectIdentifier::init(const std::vector<int>& values){

        }
    }
}