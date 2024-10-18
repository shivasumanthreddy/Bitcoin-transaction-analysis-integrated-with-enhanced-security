#!/bin/bash
time ../../../isekai.git/trunk/isekai --scheme=aurora --prove=hashproof hash.j1
cp hash.j1 hashverif.j1
cp hash.j1.in hashverif.j1.in

