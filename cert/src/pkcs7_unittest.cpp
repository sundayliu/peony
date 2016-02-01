//////////////////////////////////////////////////////////////////////////////////////////////////
// @file: crypto/pkcs/pkcs7_unittest.cpp
// @author: sundayliu
// @date: 2016.01.17
//////////////////////////////////////////////////////////////////////////////////////////////////
#include "pkcs7.h"
#include "gtest/gtest.h"
#include <iostream>

using namespace std;

/*
TEST(IndependentMethod, ResetsZero){
    //cout << "Hello" << endl;
    int i = 0;
    EXPECT_EQ(0, i);
    
    i = 12;
    EXPECT_EQ(12, i);
}

TEST(IndependentMethod, ResetsZero2){
    int i = 0;
    EXPECT_EQ(0,i);
}
*/

class PKCS7Test:public ::testing::Test{
protected:
    PKCS7Test(){
        m_pkcs7 = new tp::crypto::PKCS7("../data/test.RSA");
    }
    
    virtual ~PKCS7Test(){
        if (m_pkcs7 != NULL){
            delete m_pkcs7;
            m_pkcs7 = NULL;
        }
    }
    
    virtual void SetUp(){
        
    }
    
    virtual void TearDown(){
        
    }
    
    tp::crypto::PKCS7* m_pkcs7;
};

TEST_F(PKCS7Test, MethodExample){
    int i = 1;
    EXPECT_EQ(1, i);
}