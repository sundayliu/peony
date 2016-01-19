# -*- coding:utf-8 -*-
# author:sundayliu
# date: 2016.01.18

from __future__ import print_function
import os
import sys
import argparse

from pyasn1.type import univ

def test_asn1():
    asn1IntegerValue = univ.Integer(12)
    asn1IntegerValue = asn1IntegerValue - 2
    print(asn1IntegerValue)
    equal = univ.OctetString('abc') == 'abc'
    print(equal)

def main():
    print("asn1 parser v0.1")
    test_asn1()
if __name__ == "__main__":
    main()
