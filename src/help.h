/*
Copyright 2016 Johannes Roth johannes.roth@cryptosource.de

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef DERDEVIL_HELP_H
#define DERDEVIL_HELP_H


#include <vector>
#include <algorithm>

#include "botan/bigint.h"

using namespace std;
using byte = unsigned char;

/**
    returns a vector of bytes that represents the base256 encoding of the input

    @param n base10 value that will be encoded base256
*/
vector<byte> base256(Botan::BigInt n);

/**
    returns a vector of bytes that represents the base128 encoding of the input

    @param n base10 value that will be encoded base128
*/
vector<byte> base128(int n);

#endif
