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

#include "intmanipulator.h"

#include <random>

IntManipulator::IntManipulator(shared_ptr<DERObject> obj,
                               uint64_t randomness)
    : Manipulator(obj, randomness) {
  set_fixed_manipulations(randomness);
}

void IntManipulator::set_value(Botan::BigInt num) {
  this->derobj->raw_value = IntManipulator::to_der(num);
}

void IntManipulator::set_fixed_manipulations(uint64_t randomness) {
  Botan::BigInt base_value = this->get_value();

  /***/
  // only for testing purposes: DELETE THIS LINE LATER!!
  fixed_manipulations.push_back(base_value);
  /***/

  fixed_manipulations.push_back(base_value + 1);
  fixed_manipulations.push_back(base_value - 1);
  fixed_manipulations.push_back(base_value * 2);
  fixed_manipulations.push_back(base_value / 2);
  fixed_manipulations.push_back(base_value * 1000);
  fixed_manipulations.push_back(base_value / 1000);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(31));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(31) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(31) + 1);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(32));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(32) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(32) + 1);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(63));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(63) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(63) + 1);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(64));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(64) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(64) + 1);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(127));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(127) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(127) + 1);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(128));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(128) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(128) + 1);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(4047));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(4047) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(4047) + 1);

  fixed_manipulations.push_back(Botan::BigInt::power_of_2(4048));
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(4048) - 1);
  fixed_manipulations.push_back(Botan::BigInt::power_of_2(4048) + 1);
}

Botan::BigInt IntManipulator::get_value() { return this->from_der(); }

Botan::BigInt IntManipulator::from_der() {
  Botan::BigInt n;

  Botan::BER_Decoder dec_base(this->derobj->raw_bytes());
  Botan::BER_Decoder dec = dec_base.decode(n);

  return n;
}

vector<byte> IntManipulator::to_der(Botan::BigInt num) {
  vector<byte> result;

  Botan::DER_Encoder enc;
  enc.encode(num);

  Botan::secure_vector<byte> tmp = enc.get_contents();

  // skip tag and length to get to content value
  size_t index = int(tmp[1]);
  if (index > 128) {
    index -= 128;
  } else {
    index = 2;
  }

  for (; index < tmp.size();) {
    result.push_back(tmp[index++]);
  }

  return result;
}

size_t IntManipulator::get_fixed_manipulations_count() {
  return this->fixed_manipulations.size();
}

void IntManipulator::generate(uint64_t randomness, bool random, int index) {
  if (!random) {
    if (index == -1)
      this->set_value(this->fixed_manipulations[this->manipulation_count++]);
    else
      this->set_value(this->fixed_manipulations[index]);
  } else {
    // create random number X (number of bits) and then create a random number
    // of X bit
    std::mt19937 rng(randomness);
    // std::uniform_int_distribution<size_t> distBit(1, 4047);
    std::uniform_int_distribution<uint64_t> dist(1, (uint64_t)-1);

    this->set_value(dist(rng));
  }
}
