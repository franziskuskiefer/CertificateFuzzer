#!/bin/bash

echo "building Botan library. This might take some minutes"
sleep 2
cd Libraries/Botan-1.11.19
./configure.py
make -j4



echo "building Certificate Fuzzer"
cd ../../
cmake .
make -j4

echo "done."
