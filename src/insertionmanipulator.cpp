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

#include "insertionmanipulator.h"

#include <random>

InsertionManipulator::InsertionManipulator(shared_ptr<DERObject> obj,
                                           uint64_t randomness)
    : Manipulator(obj, randomness) {
  this->set_fixed_manipulations(randomness);
}

void InsertionManipulator::set_fixed_manipulations(uint64_t randomness) {
  size_t end_pos = this->derobj->raw_value.size();

  this->fixed_manipulations = {tuple<vector<byte>, size_t>({0}, 0),
                               tuple<vector<byte>, size_t>({0}, end_pos),
                               tuple<vector<byte>, size_t>({0}, end_pos / 2),
                               tuple<vector<byte>, size_t>({0, 1, 2, 3}, 0)};
}

size_t InsertionManipulator::get_fixed_manipulations_count() {
  return this->fixed_manipulations.size();
}

vector<tuple<vector<byte>, size_t>>
InsertionManipulator::get_fixed_manipulations(uint64_t randomness) {
  return this->fixed_manipulations;
}

void InsertionManipulator::generate(uint64_t randomness, bool random,
                                    int index) {

  this->restore_initial_values(); // revert last modification

  if (!random) {
    if (index == -1) {
      this->derobj->raw_value.insert(
          this->derobj->raw_value.begin() +
              get<1>(this->fixed_manipulations[this->manipulation_count]),
          get<0>(this->fixed_manipulations[this->manipulation_count]).begin(),
          get<0>(this->fixed_manipulations[this->manipulation_count]).end());

      this->manipulation_count++;
    } else {
      this->derobj->raw_value.insert(
          this->derobj->raw_value.begin() +
              get<1>(this->fixed_manipulations[index]),
          get<0>(this->fixed_manipulations[index]).begin(),
          get<0>(this->fixed_manipulations[index]).end());
    }
  } else {
    // randomly insert bytes into random positions
    std::mt19937 rng(randomness);
    std::uniform_int_distribution<size_t> dist(1, 5);

    size_t num_insertions = dist(rng); // do max 5 insertions
    size_t raw_value_size = this->derobj->raw_value.size();
    size_t num_bytes, pos;

    dist = std::uniform_int_distribution<size_t>(0, 9);
    std::uniform_int_distribution<size_t> dist2(0, raw_value_size - 1);
    std::uniform_int_distribution<size_t> dist3(0, 255);
    for (size_t i = 0; i < num_insertions; i++) {
      num_bytes = dist(rng); // don't insert more than 10 bytes
      for (size_t j = 0; j < num_bytes; j++) {
        if (raw_value_size > 0) {
          pos = dist2(rng);
        } else
          pos = 0;
        this->derobj->raw_value.insert(this->derobj->raw_value.begin() + pos,
                                       dist3(rng));
      }
    }

    this->manipulation_count++;
  }
}
