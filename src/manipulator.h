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

#ifndef DERDEVIL_MANIPULATOR_H
#define DERDEVIL_MANIPULATOR_H

#include <iostream>
#include <math.h>
#include <ostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include "DERObject.h"
#include "constants.h"
#include "help.h"

#include "botan/ber_dec.h"
#include "botan/bigint.h"
#include "botan/der_enc.h"
#include "botan/rng.h"

/**
 Struct that stores values that define a DERObject. Used to save and restore
 values after they have been manipulated
*/
struct derobj_values {
  byte raw_tag;
  vector<byte> raw_length;
  vector<byte> raw_value;
};

using byte = unsigned char;
using namespace std;

/**
    The (virtual) base class for all manipulator subclasses.

    The constructor of a class that inherits from this class takes a shared
   pointer to a DERObject.
    This DERObject is supposed to be a leaf node (primitive type), meaning that
   it represents one field of the X.509 certificate that is not constructed of
   other values.
    The manipulator then is able to manipulate the field content based on the
   type of the field.
    Every field gets its own subclass
*/
class Manipulator {
public:
  /**
      Constructor. Expects a leaf node (primitive type) DERObject
  */
  Manipulator(shared_ptr<DERObject> obj, unsigned int randomness);

  /**
      Generic generate method. Must be implemented by subclasses that should
     generate a mutation based on the type.
  */
  virtual void generate(unsigned int randomness, bool random,
                        int index = -1) = 0;

  /**
      Restores the values of DERObject to the values that they had when the
     constructor was called
  */
  void restore_initial_values();

  /**
      returns the number of fixed (deterministic) manipulations that are
     available
  */
  virtual size_t get_fixed_manipulations_count() = 0;

  /**
      Factory method. Returns a manipulator of an appropriate type
  */
  static shared_ptr<Manipulator> make_manipulator(shared_ptr<DERObject> obj,
                                                  unsigned int randomness);

protected:
  shared_ptr<DERObject> derobj; ///< pointer to the manipulated DERObject

  size_t manipulation_count; ///< keeps track of the number of applied
                             /// manipulations

  /**
      getter for manipulation_count
  */
  size_t get_current_manipulation_count();

  derobj_values initial_derobj_values; ///< stores the values of the DERObj that
                                       /// is passed in the constructor. Used to
  /// reset the manipulations afterwards.

  /**
      returns a vector of strings that contains all fixed string manipulations
     that can be applied to any string based type
  */
  vector<string> general_fixed_string_manipulations();

  /**
      returns a random string that has been geerated according to some rules
  */
  string general_random_string_manipulation(unsigned int randomness);

  static string long_string; ///< stores a long string that will be used to test
                             /// the capability of TLS implementations to deal
  /// with long fields in certificates

  static size_t
      long_string_count; ///< keeps track of how often long_string has been used
};

#endif
