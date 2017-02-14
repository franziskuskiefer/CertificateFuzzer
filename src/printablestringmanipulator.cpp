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

#include "printablestringmanipulator.h"

#include <random>

PrintableStringManipulator::PrintableStringManipulator(
    shared_ptr<DERObject> obj, uint64_t randomness)
    : Manipulator(obj, randomness), fixed_manipulations() {
  this->set_fixed_manipulations(randomness);
}

void PrintableStringManipulator::set_value(string str) {
  this->derobj->raw_value = this->to_der(str);
}

string PrintableStringManipulator::get_value() { return this->from_der(); }

string PrintableStringManipulator::from_der() {
  string str = "";
  for (byte b : this->derobj->raw_value) {
    str.append(1, b);
  }

  return str;
}

vector<byte> PrintableStringManipulator::to_der(string str) {
  vector<byte> result;
  if (!str.empty()) {
    for (char &c : str) {
      result.push_back(c);
    }
  } else {
    result.push_back('1');
  }
  return result;
}

size_t PrintableStringManipulator::get_fixed_manipulations_count() {
  return this->fixed_manipulations.size();
}

void PrintableStringManipulator::set_fixed_manipulations(uint64_t randomness) {
  // also use general string manipulations
  vector<string> string_manipulations =
      this->general_fixed_string_manipulations();
  for (int i = 0; i < RANDOM_STRING_MANIPULATIONS; i++) {
    string_manipulations.push_back(
        this->general_random_string_manipulation(randomness));
  }
  this->fixed_manipulations.insert(this->fixed_manipulations.end(),
                                   string_manipulations.begin(),
                                   string_manipulations.end());
}

void PrintableStringManipulator::generate(uint64_t randomness, bool random,
                                          int index) {
  if (!random) {
    if (index < 0) {
      this->set_value(this->fixed_manipulations[this->manipulation_count++]);
    } else if (this->fixed_manipulations.size()) {
      this->set_value(
          this->fixed_manipulations[index % this->fixed_manipulations.size()]);
    } else {
      this->set_value("1");
    }
  } else {
    // do random stuff
    this->set_value(this->general_random_string_manipulation(randomness));
    this->manipulation_count++;
  }
}

/*
http://luca.ntop.org/Teaching/Appunti/asn1.html

 The PrintableString type denotes an arbitrary string of printable characters
from the following character set:

A, B, ..., Z
a, b, ..., z
0, 1, ..., 9
(space) ' ( ) + , - . / : = ?

*/
