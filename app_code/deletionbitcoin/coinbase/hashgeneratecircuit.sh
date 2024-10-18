#!/bin/bash   
clang -DISEKAI_C_PARSER=0 -DTRANSACTION_LENGTH=$1 -DDELETED_DATA_LENGTH=$2 -O0 -c -emit-llvm /home/vincenzobotta/bitcoin-source/mysource/deletionbitcoin/hash.cpp       
time /home/iovino/isekai.git/trunk/isekai --scheme=aurora --r1cs=hash.j1 hash.bc                                                                                        
cp hash.j1 hashverif.j1
