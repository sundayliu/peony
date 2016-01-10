#include "foo.h"
#include "gtest/gtest.h"
#include <iostream>

TEST(IndependentMethod, ResetsZero){
    int i = 3;
    independentMethod(i);
    EXPECT_EQ(0, i);
    
    i = 12;
    independentMethod(i);
    EXPECT_EQ(0, i);
}

TEST(IndependentMethod, ResetsZero2){
    int i = 0;
    independentMethod(i);
    EXPECT_EQ(0,i);
}

class FooTest:public ::testing::Test{
protected:
    FooTest(){
        
    }
    
    virtual ~FooTest(){
        
    }
    
    virtual void SetUp(){
        
    }
    
    virtual void TearDown(){
        
    }
    
    Foo m_foo;
};

TEST_F(FooTest, MethodExample){
    int i = 0;
    m_foo.example(i);
    EXPECT_EQ(1, i);
}