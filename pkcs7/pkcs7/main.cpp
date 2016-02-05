#include <iostream>
using namespace std;

#include "pkcs7.h"

int main(int argc, char* argv[]){
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