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

Manipulator::Manipulator(shared_ptr<DERObject> obj, uint64_t randomness) {
  this->derobj = obj;
  this->manipulation_count = 0;

  // save the initial derobj values to restore later
  this->initial_derobj_values.raw_tag = obj->raw_tag;
  this->initial_derobj_values.raw_value = obj->raw_value;
  this->initial_derobj_values.raw_length = obj->raw_length;

  static bool initialized;
  // init long_string as 50mb string
  if (!initialized) {
    initialized = true;

    size_t c_start = 0;
    size_t c_end = 50 * 1024 * 1024;
    char *c = (char *)malloc(c_end);
    std::mt19937 rng(randomness);
    std::uniform_int_distribution<size_t> dist(1, 253);
    for (; c_start < c_end; c_start++) {
      *(c + c_start) = dist(rng); // avoid null terminator
    }
    // Manipulator::long_string.insert(0, string(c));
  }
}

void Manipulator::restore_initial_values() {
  this->derobj->raw_tag = this->initial_derobj_values.raw_tag;
  this->derobj->raw_length = this->initial_derobj_values.raw_length;
  this->derobj->raw_value = this->initial_derobj_values.raw_value;
}

size_t Manipulator::get_current_manipulation_count() {
  return this->manipulation_count;
}

// factory method
shared_ptr<Manipulator> Manipulator::make_manipulator(shared_ptr<DERObject> obj,
                                                      uint64_t randomness) {

  shared_ptr<Manipulator> r = nullptr;

  switch (int(obj->raw_tag)) {
  case ASN1_TYPE_INTEGER:
    r = shared_ptr<Manipulator>(new IntManipulator(obj, randomness));
    break;

  case ASN1_TYPE_OBJECT_IDENTIFIER:
    r = shared_ptr<Manipulator>(new OIDManipulator(obj, randomness));
    break;

  case ASN1_TYPE_PRINTABLESTRING:
    r = shared_ptr<Manipulator>(
        new PrintableStringManipulator(obj, randomness));
    break;

  case ASN1_TYPE_UTCTime:
    r = shared_ptr<Manipulator>(new UTCTimeManipulator(obj, randomness));
    break;

  case ASN1_TYPE_IA5STRING:
    r = shared_ptr<Manipulator>(new IA5StringManipulator(obj, randomness));
    break;

  case ASN1_TYPE_UTF8STRING:
    r = shared_ptr<Manipulator>(new UTF8StringManipulator(obj, randomness));
    break;

  case ASN1_TYPE_GeneralizedTime:
    r = shared_ptr<Manipulator>(
        new GeneralizedTimeManipulator(obj, randomness));
    break;
  }

  return r;
}

/**
    defines general manipulations that can be used for all string-based fields
*/

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

/**
    return a random string that includes random symbols
*/
string
Manipulator::general_random_string_manipulation(uint64_t randomness) {
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
