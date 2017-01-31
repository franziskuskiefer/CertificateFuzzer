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

#ifndef DERDEVIL_PRINTABLESTRINGMANIPULATOR_H
#define DERDEVIL_PRINTABLESTRINGMANIPULATOR_H

#include "manipulator.h"

/**
    sub class of Manipulator. Handles PrintableString specific manipulations on
   DERObjects
*/
class PrintableStringManipulator : public Manipulator {
public:
  PrintableStringManipulator(shared_ptr<DERObject> obj,
                             unsigned int randomness);
  void generate(unsigned int randomness, bool random, int index = -1);
  virtual size_t get_fixed_manipulations_count();

  string get_value();
  void set_value(string str);

private:
  vector<string> fixed_manipulations;
  void set_fixed_manipulations(unsigned int randomness);

  vector<string> get_fixed_manipulations();

  vector<byte> to_der(string str);
  string from_der();
};

#endif
