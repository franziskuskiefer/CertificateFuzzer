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

#include "changemanipulator.h"

#include <random>

ChangeManipulator::ChangeManipulator(DERObject &obj, uint64_t randomness)
    : Manipulator(obj, randomness) {
  this->set_fixed_manipulations(randomness);
}

void ChangeManipulator::set_fixed_manipulations(uint64_t randomness) {

  size_t end_pos = this->derobj.raw_value.size();

  // don't do anything for null values
  if (end_pos == 0) {
    return;
  }
  end_pos--;

  this->fixed_manipulations = {
      {tuple<byte, size_t>(0, 0)},
      {tuple<byte, size_t>(0, end_pos)},
      {tuple<byte, size_t>(0, end_pos / 2)},
      {tuple<byte, size_t>(0, 0), tuple<byte, size_t>(0, end_pos / 2)},
      {tuple<byte, size_t>(0, 0), tuple<byte, size_t>(0, end_pos)},
      {tuple<byte, size_t>(0, end_pos / 2), tuple<byte, size_t>(0, end_pos)},
      {tuple<byte, size_t>(0, 0), tuple<byte, size_t>(0, end_pos / 2),
       tuple<byte, size_t>(0, end_pos)}};
}

size_t ChangeManipulator::get_fixed_manipulations_count() {
  return this->fixed_manipulations.size();
}

vector<vector<tuple<byte, size_t>>>
ChangeManipulator::get_fixed_manipulations() {
  return this->fixed_manipulations;
}

void ChangeManipulator::generate(uint64_t randomness, bool random, int index) {

  this->restore_initial_values(); // revert last modification

  if (!random) {
    if (index == -1) {
      for (tuple<byte, size_t> t :
           this->fixed_manipulations[this->manipulation_count]) {
        this->derobj.raw_value[get<1>(t)] = get<0>(t);
      }

      this->manipulation_count++;
    } else {
      for (tuple<byte, size_t> t : this->fixed_manipulations[index]) {
        this->derobj.raw_value[get<1>(t)] = get<0>(t);
      }
    }
  } else {
    // choose random interval
    // randomly change the values in this interval
    std::mt19937 rng(randomness);

    size_t rand_range = this->derobj.raw_value.size();
    std::uniform_int_distribution<size_t> dist(0, rand_range - 1);

    // don't do anything for null values
    if (rand_range == 0) {
      this->manipulation_count++;
      return;
    }

    // determine the range where the bytes are changed
    size_t pos_start = dist(rng);
    size_t pos_end = dist(rng);
    if (pos_start > pos_end) {
      size_t tmp = pos_start;
      pos_start = pos_end;
      pos_end = tmp;
    }

    // create random vector with pos_end-pos_start bytes
    vector<byte> rand_bytes;

    dist = std::uniform_int_distribution<size_t>(0, 255);
    for (int i = 0; i < (pos_end - pos_start) + 1; i++) {
      rand_bytes.push_back(dist(rng));
    }

    // change bytes
    for (int i = 0; i < (pos_end - pos_start) + 1; i++) {
      this->derobj.raw_value[i + pos_start] = rand_bytes[i];
    }

    this->manipulation_count++;
  }
}
