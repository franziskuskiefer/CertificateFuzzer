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

#include "ia5stringmanipulator.h"

IA5StringManipulator::IA5StringManipulator(shared_ptr<DERObject> obj) : Manipulator(obj) {
    this->set_fixed_manipulations();
}



void IA5StringManipulator::set_value(string str) {
    this->derobj->raw_value = IA5StringManipulator::to_der(str);
}


string IA5StringManipulator::get_value() {
    return this->from_der();
}


string IA5StringManipulator::from_der() {
    string str = "";
    for (byte b : this->derobj->raw_value) {
        str.append(1, b);
    }

    return str;
}

vector<byte> IA5StringManipulator::to_der(string str) {
    vector<byte> result;
    for(char& c : str) {
        result.push_back(c);
    }
    return result;

}

size_t IA5StringManipulator::get_fixed_manipulations_count() {
    return this->fixed_manipulations.size();
}


void IA5StringManipulator::set_fixed_manipulations() {

    // also use general string manipulations
    vector<string> string_manipulations = this->general_fixed_string_manipulations();
    for (int i=0; i<RANDOM_STRING_MANIPULATIONS; i++) {
        string_manipulations.push_back(this->general_random_string_manipulation());
    }
    this->fixed_manipulations.insert(this->fixed_manipulations.end(), string_manipulations.begin(), string_manipulations.end());

}

void IA5StringManipulator::generate(bool random, int index) {
    if (!random) {
        if (index == -1)
            this->set_value(this->fixed_manipulations[this->manipulation_count++]);
        else
            this->set_value(this->fixed_manipulations[index]);
    }
    else {
        // do random stuff
        this->set_value(this->general_random_string_manipulation());
        this->manipulation_count++;
    }
}

/*
http://luca.ntop.org/Teaching/Appunti/asn1.html

 The IA5String type denotes an arbtrary string of IA5 characters. IA5 stands for International Alphabet 5, which is the same as ASCII.
 The character set includes non- printing control characters. An IA5String value can have any length, including zero. This type is a string type.

*/
