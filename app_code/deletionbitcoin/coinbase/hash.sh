#!/bin/bash
#clang -DISEKAI_C_PARSER=0 -DTRANSACTION_LENGTH=$1 -DDELETED_DATA_LENGTH=$2 -O0 -c -emit-llvm hash.cpp
#../isekai --scheme=aurora --arith=hash.arith hash.bc
#../isekai --scheme=aurora --r1cs=hash.j1 hash.bc
/home/iovino/isekai.git/trunk --scheme=aurora --prove=hashproof hash.j1
cp hash.j1 hashverifier.j1
cp hash.j1.in hashverifier.j1.in

