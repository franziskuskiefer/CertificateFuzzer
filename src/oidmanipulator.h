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

#ifndef DERDEVIL_OIDMANIPULATOR_H
#define DERDEVIL_OIDMANIPULATOR_H

#include "manipulator.h"

/**
    sub class of Manipulator. Handles OID specific manipulations on DERObjects
*/
class OIDManipulator : public Manipulator {
public:
  OIDManipulator(shared_ptr<DERObject> obj, unsigned int randomness);
  void generate(unsigned int randomness, bool random, int index = -1);
  size_t get_fixed_manipulations_count();

  vector<int> get_value();
  void set_value(vector<int> oid);

private:
  vector<vector<int>> fixed_manipulations;
  void set_fixed_manipulations(unsigned int randomness);

  vector<vector<int>> get_fixed_manipulations();

  vector<byte> to_der(vector<int> oid);
  vector<int> from_der();
};

#endif
