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

#include "oidmanipulator.h"

#include <random>

OIDManipulator::OIDManipulator(DERObject &obj, uint64_t randomness)
    : Manipulator(obj, randomness) {
  this->set_fixed_manipulations(randomness);
}

void OIDManipulator::set_fixed_manipulations(uint64_t randomness) {
  this->fixed_manipulations.push_back({1, 2, 3, 4});
  this->fixed_manipulations.push_back({2, 1, 4});
  this->fixed_manipulations.push_back({2, 1, 4, 4});
}

vector<int> OIDManipulator::get_value() { return this->from_der(); }

void OIDManipulator::set_value(vector<int> oid) {
  this->derobj.raw_value = this->to_der(oid);
  this->derobj.raw_length =
      DERObject::int_to_raw_length(this->derobj.raw_value.size());
}

size_t OIDManipulator::get_fixed_manipulations_count() {
  return this->fixed_manipulations.size();
}

vector<int> OIDManipulator::from_der() {

  // first two numbers are in the first byte, decode as follows
  int index = 0;
  int sum;
  vector<int> oid;
  byte current_byte;

  current_byte = this->derobj.raw_value[index];
  oid.push_back(int(current_byte) / 40);
  oid.push_back(int(current_byte) % 40);

  // continue with variable length quantity
  while (index < this->derobj.raw_value.size() - 1) {
    current_byte = this->derobj.raw_value[++index];
    if (int(current_byte) <= 127) {
      oid.push_back(int(current_byte));
    } else {
      vector<int> tmp;
      while (int(current_byte) >= 128) {
        tmp.push_back(int(current_byte) - 128);
        current_byte = this->derobj.raw_value[++index];
      }
      tmp.push_back(int(current_byte));

      sum = 0;
      for (int i = 0; i < tmp.size(); i++) {
        sum += tmp[i] * pow(128, (tmp.size() - i - 1));
      }
      oid.push_back(sum);
    }
  }
  return oid;
}

vector<byte> OIDManipulator::to_der(vector<int> oid) {
  vector<byte> der;

  // first byte is 40*X + Y where X is the first number of the oid and Y the
  // second
  der.push_back(40 * oid[0] + oid[1]);

  vector<byte> tmp;
  for (int i = 2; i < oid.size(); i++) {
    if (oid[i] >= 128) {
      tmp = base128(oid[i]);
      der.insert(der.end(), tmp.begin(), tmp.end());
    } else {
      der.push_back(oid[i]);
    }
  }

  return der;
}

void OIDManipulator::generate(uint64_t randomness, bool random, int index) {
  if (!random) {
    if (index == -1)
      this->set_value(this->fixed_manipulations[this->manipulation_count++]);
    else
      this->set_value(this->fixed_manipulations[index]);
  } else {
    std::mt19937 rng(randomness);
    std::uniform_int_distribution<int> dist(0, 254);
    std::bernoulli_distribution bdist;

    vector<int> result;

    // first octet is (40 * value1 + value2) - Respect this in 50% of cases
    if (bdist(rng)) {
      result.push_back((40ULL * dist(rng) + dist(rng)) % 256);
    } else {
      result.push_back(dist(rng));
    }

    // randomly add some more values
    std::uniform_int_distribution<size_t> dist2(1, 9);
    for (int i = 0; i < dist2(rng); i++) {
      int x = dist(rng);
      std::cout << x << std::endl;
      result.push_back(x);
    }

    this->set_value(result);
  }
}
