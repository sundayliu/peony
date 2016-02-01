#include <iostream>
using namespace std;

#include "pkcs7.h"

int main(int argc, char* argv[]){
  cout << "=====PKCS7 Parser=====" << endl;

  tp::crypto::PKCS7* pkcs7 = new tp::crypto::PKCS7("../data/test.RSA");
  if (pkcs7 != NULL){
    delete pkcs7;
  }

  return 0;
}