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

#include "utctimemanipulator.h"

#include <random>

UTCTimeManipulator::UTCTimeManipulator(shared_ptr<DERObject> obj,
                                       uint64_t randomness)
    : Manipulator(obj, randomness) {
  this->set_fixed_manipulations(randomness);
}

void UTCTimeManipulator::set_value(string str) {
  this->derobj->raw_value = UTCTimeManipulator::to_der(str);
}

string UTCTimeManipulator::get_value() { return this->from_der(); }

string UTCTimeManipulator::from_der() {
  string str = "";
  for (byte b : this->derobj->raw_value) {
    str.append(1, b);
  }

  return str;
}

vector<byte> UTCTimeManipulator::to_der(string str) {
  vector<byte> result;
  for (char &c : str) {
    result.push_back(c);
  }
  return result;
}

size_t UTCTimeManipulator::get_fixed_manipulations_count() {
  return this->fixed_manipulations.size();
}

void UTCTimeManipulator::set_fixed_manipulations(uint64_t randomness) {
  this->fixed_manipulations.push_back("910230234540Z");

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

string UTCTimeManipulator::get_random_time(uint64_t randomness) {
  string result = "";
  std::mt19937 rng(randomness);
  std::uniform_int_distribution<size_t> dist(0, 9);
  std::uniform_int_distribution<size_t> dist2(0, 5);

  // first add 10 random digits for YYMMDDhhmm
  for (int i = 0; i < 10; i++) {
    result.insert(result.end(), (char)dist(rng) + 48);
  }

  // choose between 6 possible forms
  int decision = dist2(rng);

  if (decision == 0) {
    result.insert(result.end(), 'Z');
  } else if (decision == 1) {
    result.insert(result.end(), '+');
    for (int i = 0; i < 4; i++) {
      result.insert(result.end(), (char)dist(rng) + 48);
    }
  } else if (decision == 2) {
    result.insert(result.end(), '-');
    for (int i = 0; i < 4; i++) {
      result.insert(result.end(), (char)dist(rng) + 48);
    }
  } else if (decision == 3) {
    for (int i = 0; i < 2; i++) {
      result.insert(result.end(), (char)dist(rng) + 48);
    }
    result.insert(result.end(), 'Z');
  } else if (decision == 4) {
    for (int i = 0; i < 2; i++) {
      result.insert(result.end(), (char)dist(rng) + 48);
    }
    result.insert(result.end(), '+');
    for (int i = 0; i < 4; i++) {
      result.insert(result.end(), (char)dist(rng) + 48);
    }
  } else if (decision == 5) {
    for (int i = 0; i < 2; i++) {
      result.insert(result.end(), (char)dist(rng) + 48);
    }
    result.insert(result.end(), '-');
    for (int i = 0; i < 4; i++) {
      result.insert(result.end(), (char)dist(rng) + 48);
    }
  }
  return result;
}

void UTCTimeManipulator::generate(uint64_t randomness, bool random,
                                  int index) {
  if (!random) {
    if (index == -1)
      this->set_value(this->fixed_manipulations[this->manipulation_count++]);
    else
      this->set_value(this->fixed_manipulations[index]);
  } else {
    std::mt19937 rng(randomness);
    std::bernoulli_distribution dist;

    if (dist(rng)) {
      this->set_value(general_random_string_manipulation(randomness));
    } else {
      this->set_value(get_random_time(randomness));
    }
  }
}

/*
http://luca.ntop.org/Teaching/Appunti/asn1.html

YYMMDDhhmmZ
YYMMDDhhmm+hh'mm'
YYMMDDhhmm-hh'mm'
YYMMDDhhmmssZ
YYMMDDhhmmss+hh'mm'
YYMMDDhhmmss-hh'mm'

where:

    YY is the least significant two digits of the year

    MM is the month (01 to 12)

    DD is the day (01 to 31)

    hh is the hour (00 to 23)

    mm are the minutes (00 to 59)

    ss are the seconds (00 to 59)

    Z indicates that local time is GMT, + indicates that local time is later
than GMT, and - indicates that local time is earlier than GMT

    hh' is the absolute value of the offset from GMT in hours

    mm' is the absolute value of the offset from GMT in minutes

*/
