#include "foo.h"
#include <iostream>
using namespace std;

int main(){
    cout << "do stuff" << endl;
    int x =4;
    cout << x << endl;
    independentMethod(x);
    cout << x << endl;
    Foo foo;
    foo.example(x);
    cout << x << endl;
    return 0;
}