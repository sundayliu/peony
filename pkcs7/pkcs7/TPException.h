#ifndef __CRYPTO_TP_EXCEPTION_H__
#define __CRYPTO_TP_EXCEPTION_H__

#include <exception>
#include <string>
namespace tp{
    namespace crypto{
        class TPException :public std::exception{
        public:
            TPException(const char* message) :std::exception(message){

            }
        };
    }
}

#endif