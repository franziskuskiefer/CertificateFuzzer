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

#ifndef DERDEVIL_DEROBJECT_H
#define DERDEVIL_DEROBJECT_H

#include <fstream>
#include <vector>
#include <stack>
#include <iterator>
#include <iostream>
#include <sstream>
#include <list>
#include <math.h>
#include <memory>
#include <algorithm>
#include <string>

using byte = unsigned char;
using namespace std;

/**
    Data type that is used to represent fields of a DER encoded X.509 certificate in a tree structure
*/
class DERObject {
	public:
        DERObject();

        // The following 3 attributes contain the TLV values
        byte raw_tag; ///< stores the tag in byte encoding
        vector<byte> raw_length; ///< stores the length in byte encoding
        vector<byte> raw_value; ///< stores the data of the field in byte encoding


        string name; ///< is assign to specific DERObjects that represent a named part of a certificate
        bool pseudo_constructed; ///< for things like OCTET STRINGs that are not really constructed, but contain ASN.1 data as if it was an constructed type

        // the attributes below are mainly used during build-up of the tree
        // and not necessarily maintained when modifying the tree

        vector<shared_ptr<DERObject>> children;     ///< stores pointers children if it's a constructed type (not necessarily maintained after tree construction)
		shared_ptr<DERObject> parent;               ///< reference to the parent node (not necessarily maintained after tree construction)
        int pos;                                    ///< only used during construction of the tree

        bool root;                                  ///< Store whether this object is a root node
        bool is_constructed();                      ///< returns true for constructed types
        vector<byte> raw_bytes();                   ///< returns the concatenation of the complete TLV triple for primitive types and the concatenation of all children for constructed types. Called on the root node it returns the complete X.509 certificate in DER encoding

        void recalculate_lengths();                 ///< If called on an intermediate node it will recalculate its length and the length of all subsequent children to adjust for changes in the data of its children

        static vector<byte> int_to_raw_length(size_t n);    ///< converts a base 10 integer to the DER encoding that is used for raw_length
        static int raw_length_to_int(vector<byte> raw_length);  ///< converts a vector that contains the DER encoding of the length into a base 10 integer

        shared_ptr<DERObject> get_object_by_name(const string str); ///< Returns a pointer to an object with the given name iff a child with this name exists.


    private:
        size_t get_value_length();          ///< returns the size of raw_value for primitive types and the size of the concatentation for constructed types.


};


#endif
