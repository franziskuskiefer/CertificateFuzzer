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

#include "DERObject.h"

using namespace std;
using byte = unsigned char;


DERObject::DERObject() {
    this->parent = nullptr;
    this->root = false;
    this->name = "";
    this->pseudo_constructed = false;
    this->pos = 0;
    this->raw_tag = 0;
    this->raw_value.clear();
    this->raw_length.clear();
}


// Returns a shared_ptr for the DERObject with the specified name
// Note: Check for nullptr before using the result
shared_ptr<DERObject> DERObject::get_object_by_name (const string str) {
    shared_ptr<DERObject> result = nullptr;

    for (shared_ptr<DERObject> child : this->children) {
         if (child->name.compare(str) == 0) {
            result = child;
            break;
         }
         result = child->get_object_by_name(str);
         if (result != nullptr)
            break;
    }
    return result;
}

void DERObject::recalculate_lengths() {
    this->raw_length = DERObject::int_to_raw_length(this->get_value_length());
    for (shared_ptr<DERObject> child : this->children) {
        child->recalculate_lengths();
    }
}

// returns the TLV of the object as byte vector
vector<byte> DERObject::raw_bytes() {
    vector<byte> result;

    // primitive, return value
    if (!this->is_constructed()) {
        result.push_back(raw_tag);
        result.insert(result.end(), raw_length.begin(), raw_length.end());
        result.insert(result.end(), raw_value.begin(), raw_value.end());
        return result;
    }

    // constructed
    // first add tag and then length to result
    result.push_back(this->raw_tag);

    for (byte b : this->raw_length) {
        result.push_back(b);
    }


    // for pseudo_constructed BIT STRING add leading zero byte
    if (this->pseudo_constructed && int(this->raw_tag) == 3) {
        result.push_back(0);
    }

    // add all children
    vector<byte> tmp;
    for (shared_ptr<DERObject> child : this->children) {
        tmp = child->raw_bytes();
        for (byte b : tmp) {
            result.push_back(b);
        }
    }

    return result;
}

bool DERObject::is_constructed() {
    if ((int(this->raw_tag) & 32) == 32 or this->pseudo_constructed)
        return true;
    return false;
}

size_t DERObject::get_value_length() {
    // for primitive simply return the length of the value vector
    if (!this->is_constructed()) {
        return this->raw_value.size();
    }
    // for constructed, get the sum of all children value sizes + calculate the length of each child + 1 for tag
    else {
        size_t tmp;
        size_t result = 0;

        // +1 for zero byte
        if (this->pseudo_constructed and int(this->raw_tag) == 3)
            result += 1;

        for (shared_ptr<DERObject> child : this->children) {
            tmp = child->get_value_length();
            result += tmp;  // add value bytes
            result += DERObject::int_to_raw_length(tmp).size();   // add length bytes
            result += 1;  // add tag byte
        }
        return result;
    }
}

// calculates the length that the raw_length vector represents
int DERObject::raw_length_to_int(vector<byte> raw_length) {
    int length = 0;

    // only 1 byte means it's <= 127
    if (raw_length.size() == 1) {
        return int(raw_length[0]);
    }

    // sum over all bytes except the first one (base 256)
    for (int i=raw_length.size()-2; i>=0; i--) {
        length += int(raw_length[i+1]) * pow(256, raw_length.size() - 2 - i);
    }
    return length;
}


// calculates the der encoding for the given length
vector<byte> DERObject::int_to_raw_length(size_t n) {
    vector<byte> result;

    // short form, only 1 byte used
    if (n <= 127) {
        result.push_back(n);
        return result;
    }
    // long form: first byte encodes number of following octets, base256
    else {
        size_t remainder;
        while (n != 0) {
           remainder = n % 256 ;
           n = n / 256 ;
           result.push_back(remainder);
        }
        result.push_back(128 + result.size());    // length byte of the length encoding
        reverse(result.begin(), result.end());    // reverse everything
        return result;
    }
}
