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

#ifndef _BASE64_H_
#define _BASE64_H_

#include <string>

/**
    Encodes a string in base64

    @param bytes_to_encode the c-string that is to be encoded
    @param len length of string
*/
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int len);


/**
    Decodes a string from base64

    @param s c-string to be decoded
*/
std::string base64_decode(std::string const& s);

#endif
