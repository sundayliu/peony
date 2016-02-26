#include <iostream>
#include <string>
using namespace std;

#include "pkcs7.h"

#define LIB_SUFFIX_NAME ".so"
#define LIB_SUFFIX_LEN (sizeof(LIB_SUFFIX_NAME) -1)

struct CACHE_SO_ITEM{
    uint32_t crc;
    uint32_t size;
    uint32_t ctime;
    uint32_t mtime;
    string name;
};

void test(){
    cout << "===test===" << endl;
    cout << LIB_SUFFIX_NAME << endl;
    cout << LIB_SUFFIX_LEN << endl;

    string test = "TEST\0TESTHELLO";
    cout << test << endl;

    cout << sizeof(CACHE_SO_ITEM) << endl;
    cout << sizeof(string) << endl;
    cout << "===test===" << endl;
}

int main(int argc, char* argv[]){
    test();
    return 0;
    cout << "=====PKCS7 Parser=====" << endl;

    //tp::crypto::PKCS7* pkcs7 = new tp::crypto::PKCS7("../data/test.RSA");
    //if (pkcs7 != NULL){
    //    delete pkcs7;
    //}

    //cout << "=====CERT.DSA=====" << endl;
    //tp::crypto::PKCS7* dsa = new tp::crypto::PKCS7("../data/CERT.DSA");
    //if (dsa != NULL){
    //    delete dsa;
    //}

    cout << "=====TEST.EC=====" << endl;
    tp::crypto::PKCS7* ec = new tp::crypto::PKCS7("../data/TEST.EC");
    if (ec != NULL){
        delete ec;
    }

    return 0;
}