#!/bin/bash
#cp hash.j1.in hashverif.j1.in
{ time /home/iovino/isekai.git/trunk/isekai --scheme=aurora --verif=hashproof hashverif.j1; } 2>> outver

