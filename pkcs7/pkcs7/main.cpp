#include <iostream>
#include <string>
#include <vector>
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

struct CACHE_IPA_ITEM{
    int64_t size;
    uint64_t mtime;
    uint64_t ctime;
    uint8_t digest[20];
};

bool need_verify(const char* name){
	if (name == NULL){
		return false;
	}

	string temp = name;
	for (string::size_type i = 0; i < temp.size(); i++){
		if (temp[i] >= 'A' && temp[i] <= 'Z'){
			temp[i] = temp[i] + 'a' - 'A';
		}
	}

	char pattern[3][8] = { 0 };
	pattern[0][0] = '.', pattern[0][1] = 's', pattern[0][2] = 'o', pattern[0][3] = '\0';
	pattern[1][0] = '.', pattern[1][1] = 'd', pattern[1][2] = 'e', pattern[1][3] = 'x', pattern[1][4] = '\0';
	pattern[2][0] = '.', pattern[2][1] = 'd', pattern[2][2] = 'l', pattern[2][3] = 'l', pattern[2][4] = '\0';

	for (int i = 0; i < 3; i++){
		int len = strlen(pattern[i]);
		bool match = false;
		for (int j = 0; j < len; j++){
			if (temp[temp.size() - j - 1] == pattern[i][len - j - 1]){
				if (j == len - 1){
					match = true;
				}
				continue;
			}
			else{
				break;
			}
		}

		if (match){
			return true;
		}
	}

	return false;
}

void test(){
    cout << "===test===" << endl;
    cout << LIB_SUFFIX_NAME << endl;
    cout << LIB_SUFFIX_LEN << endl;

    vector<int> values;
    for (int i = 0; i < 10; i++){
        values.push_back(i);
    }
    {
        vector<uint8_t> a;
        vector<uint8_t> b;
        for (int i = 0; i < 10; i++){
            a.push_back(i + 'A');
            b.push_back(i + 'A');
        }

        vector<uint8_t> c = a;
        for (unsigned i = 0; i < c.size(); i++){
            cout << c[i] << " ";
        }
        
    }

    string out = "";
    for (vector<int>::size_type i = 0; i < values.size(); ++i){
        char temp[16] = { 0 };
        sprintf_s(temp, sizeof(temp), "%d", values[i]);
        out += temp;
        out += ".";
    }
    cout << "ObjectIdentifier: " << out << endl;


    CACHE_IPA_ITEM ipa1 = { 0 };
    {
        CACHE_IPA_ITEM temp;
        temp.size = 100;
        temp.ctime = 0;
        temp.mtime = 0;
        memset(temp.digest, 0x31, sizeof(temp.digest));
        ipa1 = temp;
    }

    cout << ipa1.size << endl;
    cout << ipa1.digest[19] << endl;

    string test = "TEST\0TESTHELLO";
    cout << test << endl;

    cout << sizeof(CACHE_SO_ITEM) << endl;
    cout << sizeof(string) << endl;
    cout << "===test===" << endl;

	cout << need_verify("libtersafe.so") << endl;
	cout << need_verify("libtersafe.dex") << endl;
	cout << need_verify("libtersafe.png") << endl;
}

int main(int argc, char* argv[]){
    test();
    return 0;
    cout << "=====PKCS7 Parser=====" << endl;

    tp::crypto::PKCS7* pkcs7 = new tp::crypto::PKCS7("../data/test.RSA");
    if (pkcs7 != NULL){
        delete pkcs7;
    }

    //cout << "=====CERT.DSA=====" << endl;
    //tp::crypto::PKCS7* dsa = new tp::crypto::PKCS7("../data/CERT.DSA");
    //if (dsa != NULL){
    //    delete dsa;
    //}

    //cout << "=====TEST.EC=====" << endl;
    //tp::crypto::PKCS7* ec = new tp::crypto::PKCS7("../data/TEST.EC");
    //if (ec != NULL){
    //    delete ec;
    //}

    return 0;
}