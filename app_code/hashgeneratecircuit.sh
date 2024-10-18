#!/bin/bash
clang -DISEKAI_C_PARSER=0 -DTRANSACTION_LENGTH=64 -DDELETED_DATA_LENGTH=64 -O0 -c -emit-llvm ../hash.cpp
{ time /home/iovino/isekai.git/trunk/isekai --scheme=aurora --r1cs=hash.j1 hash.bc; } 2>> outgen
cp hash.j1 hashverif.j1
#cp hash.j1.in hashverif.j1.in

