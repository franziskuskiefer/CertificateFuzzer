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

#include "help.h"

using byte = unsigned char;
using namespace std;

vector<byte> base256(Botan::BigInt n) {
    vector<byte> result;
    int remainder = 0;

    while (n != 0) {
        remainder = n % 256;
        n = n / 256;
        result.push_back(remainder);
    }
    reverse(result.begin(), result.end());
    return result;
}


// base 128 with MSB set to 1 for every value but the last one
vector<byte> base128(int n) {
    vector<byte> result;
    int remainder = 0;

    bool first = true;
    while (n != 0) {

        remainder = n % 128;
        n = n / 128;

        // first element is actually the last one (algorithm pushes remainder which has to be read in reversed order) - don't add 128 to last byte
        if (first) {
            result.push_back(remainder);
            first = false;
        }
        else {
            result.push_back(remainder+128);
        }
    }
    reverse(result.begin(), result.end());
    return result;
}

/**
    returns a vector of random strings that contains (in order):
    YY (or YY if YYYY = true): Year
    MM: Month
    DD: Day
    HH: Hour
    mm: minutes
    ss: seconds
    fff: miliseconds
    +hhmm or -hhmm: offset for difference of local and UTC time
*/
vector<string> random_YYMMDDHHmmssfff_hhmm(bool YYYY = false) {
    Botan::RandomNumberGenerator *rng = Botan::RandomNumberGenerator::make_rng();
    Botan::BigInt r;
    Botan::BigInt min_val;
    Botan::BigInt max_val;

    vector<string> s;

    // add YY / YYYY
    if (YYYY) {
        min_val = 0; max_val = 9999;

    }
//    Botan::BigInt length = r.random_integer(*rng, min_val, max_val);
}





