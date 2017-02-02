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

#include "manipulator.h"
#include "generalizedtimemanipulator.h"
#include "ia5stringmanipulator.h"
#include "intmanipulator.h"
#include "oidmanipulator.h"
#include "printablestringmanipulator.h"
#include "utctimemanipulator.h"
#include "utf8manipulator.h"

#include <random>

string Manipulator::long_string = string("");
size_t Manipulator::long_string_count = 0;

Manipulator::Manipulator(DERObject &obj, uint64_t randomness) : derobj(obj) {
  this->manipulation_count = 0;

  // save the initial derobj values to restore later
  this->initial_derobj_values.raw_tag = obj.raw_tag;
  this->initial_derobj_values.raw_value = obj.raw_value;
  this->initial_derobj_values.raw_length = obj.raw_length;

  static bool initialized;
  // init a long_string
  if (!initialized) {
    initialized = true;

    size_t c_start = 0;
    size_t c_end = 3 * 1024 * 1024;
    char *c = (char *)malloc(c_end);
    std::mt19937 rng(randomness);
    std::uniform_int_distribution<size_t> dist(1, 253);
    for (; c_start < c_end - 1; c_start++) {
      *(c + c_start) = dist(rng);
    }
    c[c_end - 1] = '\0';
    Manipulator::long_string.insert(0, string(c));
    free(c);
  }
}

void Manipulator::restore_initial_values() {
  this->derobj.raw_tag = this->initial_derobj_values.raw_tag;
  this->derobj.raw_length = this->initial_derobj_values.raw_length;
  this->derobj.raw_value = this->initial_derobj_values.raw_value;
}

size_t Manipulator::get_current_manipulation_count() {
  return this->manipulation_count;
}

// factory method
unique_ptr<Manipulator> Manipulator::make_manipulator(DERObject obj,
                                                      uint64_t randomness) {
  switch (int(obj.raw_tag)) {
  case ASN1_TYPE_INTEGER:
    return unique_ptr<Manipulator>(new IntManipulator(obj, randomness));
  case ASN1_TYPE_OBJECT_IDENTIFIER:
    return unique_ptr<Manipulator>(new OIDManipulator(obj, randomness));
  case ASN1_TYPE_PRINTABLESTRING:
    return unique_ptr<Manipulator>(
        new PrintableStringManipulator(obj, randomness));
  case ASN1_TYPE_UTCTime:
    return unique_ptr<Manipulator>(new UTCTimeManipulator(obj, randomness));
  case ASN1_TYPE_IA5STRING:
    return unique_ptr<Manipulator>(new IA5StringManipulator(obj, randomness));
  case ASN1_TYPE_UTF8STRING:
    return unique_ptr<Manipulator>(new UTF8StringManipulator(obj, randomness));
  case ASN1_TYPE_GeneralizedTime:
    return unique_ptr<Manipulator>(
        new GeneralizedTimeManipulator(obj, randomness));
  default:
    return nullptr;
  }
}

vector<string> Manipulator::general_fixed_string_manipulations() {
  vector<string> r;

  char nullterminator = '\0';
  r.push_back("");

  string s;
  s = "null";
  s += nullterminator;
  s += "terminator";
  r.push_back(s);

  // don't do it too often
  if (long_string_count < 14) {
    r.push_back(long_string);
    long_string_count++;
  }

  return r;
}

// Generate a random string.
string Manipulator::general_random_string_manipulation(uint64_t randomness) {
  std::mt19937 rng(randomness);
  std::uniform_int_distribution<size_t> dist(10, 1000);
  int length = dist(rng);

  vector<string> charPool = {
      "a",  "A",  "b",  "B",  "c",  "C",  "d",  "D",  "e",  "E",  "f",  "F",
      "g",  "G",  "h",  "H",  "i",  "I",  "j",  "J",  "k",  "K",  "l",  "L",
      "m",  "M",  "n",  "N",  "o",  "O",  "p",  "P",  "q",  "Q",  "r",  "R",
      "s",  "S",  "t",  "T",  "u",  "U",  "v",  "V",  "w",  "W",  "x",  "X",
      "y",  "Y",  "z",  "Z",  "1",  "2",  "3",  "4",  "5",  "6",  "7",  "8",
      "9",  "ä",  "ö",  "ü",  "!",  "\"", "'",  "§",  "$",  "%",  "&",  "/",
      "(",  ")",  "=",  "?",  "ß",  "*",  "+",  "#",  "-",  ".",  ":",  "_",
      ",",  ";",  "%s", "%f", "%d", "%i", "%u", "%o", "%e", "%c", "%a", "%p",
      "%n", "%g", "%G", "%F", "%A", "%x", "%X"

  };

  // construct random string s
  string s = "";
  dist = std::uniform_int_distribution<size_t>(0, charPool.size() - 1);
  for (int i = 0; i < length; i++) {
    s += charPool[dist(rng)];
  }
  return s;
}
