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

#ifndef DERDEVIL_INTMANIPULATOR_H
#define DERDEVIL_INTMANIPULATOR_H


#include "manipulator.h"

/**
    sub class of Manipulator. Handles integer specific manipulations on DERObjects
*/
class IntManipulator : public Manipulator {
    public:
        IntManipulator(shared_ptr<DERObject> obj);

        void generate(bool random, int index=-1);
        size_t get_fixed_manipulations_count();

        Botan::BigInt get_value();
        void set_value(Botan::BigInt num);



    private:
        vector<Botan::BigInt> fixed_manipulations;
        void set_fixed_manipulations();

        vector<Botan::BigInt> get_fixed_manipulations();


        vector<byte> to_der(Botan::BigInt  num);
        Botan::BigInt from_der();
};

#endif
