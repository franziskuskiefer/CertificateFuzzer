#!/bin/bash

echo "building Botan library. This might take some minutes"
sleep 2
cd Libraries/Botan-1.11.19
./configure.py --disable-shared --via-amalgamation
make -j16



echo "building Certificate Fuzzer"
cd ../../
cmake .
make -j16

echo "done."
