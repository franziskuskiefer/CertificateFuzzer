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


#include "utf8manipulator.h"

UTF8StringManipulator::UTF8StringManipulator(shared_ptr<DERObject> obj) : Manipulator(obj) {
    this->set_fixed_manipulations();
}



void UTF8StringManipulator::set_value(string str) {
    this->derobj->raw_value = UTF8StringManipulator::to_der(str);
}


string UTF8StringManipulator::get_value() {
    return this->from_der();
}


string UTF8StringManipulator::from_der() {
    string str(reinterpret_cast<const char *>(&this->derobj->raw_value[0]), this->derobj->raw_value.size());
    Botan::Charset::transcode(str, Botan::LOCAL_CHARSET, Botan::UTF8_CHARSET);

    return str;
}

vector<byte> UTF8StringManipulator::to_der(string str) {
    Botan::Charset::transcode(str, Botan::UTF8_CHARSET, Botan::LOCAL_CHARSET);

    vector<byte> result;
    for(char& c : str) {
        result.push_back(c);
    }
    return result;

}

size_t UTF8StringManipulator::get_fixed_manipulations_count() {
    return this->fixed_manipulations.size();
}


void UTF8StringManipulator::set_fixed_manipulations() {

    // also use general string manipulations
    vector<string> string_manipulations = this->general_fixed_string_manipulations();
    for (int i=0; i<RANDOM_STRING_MANIPULATIONS; i++) {
        string_manipulations.push_back(this->general_random_string_manipulation());
    }
    this->fixed_manipulations.insert(this->fixed_manipulations.end(), string_manipulations.begin(), string_manipulations.end());
}

void UTF8StringManipulator::generate(bool random, int index) {
    if (!random) {
        if (index == -1)
            this->set_value(this->fixed_manipulations[this->manipulation_count++]);
        else
            this->set_value(this->fixed_manipulations[index]);
    }
    else {
        // do random stuff
        this->set_value(this->general_random_string_manipulation());
        this->manipulation_count++;;
    }
}


