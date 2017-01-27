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

#include "generalizedtimemanipulator.h"

GeneralizedTimeManipulator::GeneralizedTimeManipulator(shared_ptr<DERObject> obj) : Manipulator(obj) {
    this->set_fixed_manipulations();
}



void GeneralizedTimeManipulator::set_value(string str) {
    this->derobj->raw_value = GeneralizedTimeManipulator::to_der(str);
}


string GeneralizedTimeManipulator::get_value() {
    return this->from_der();
}


string GeneralizedTimeManipulator::from_der() {
    string str = "";
    for (byte b : this->derobj->raw_value) {
        str.append(1, b);
    }

    return str;
}

vector<byte> GeneralizedTimeManipulator::to_der(string str) {
    vector<byte> result;
    for(char& c : str) {
        result.push_back(c);
    }
    return result;

}

size_t GeneralizedTimeManipulator::get_fixed_manipulations_count() {
    return this->fixed_manipulations.size();
}

string GeneralizedTimeManipulator::get_random_time() {
    string result = "";

    Botan::BigInt x;
    Botan::RandomNumberGenerator* rng = Botan::RandomNumberGenerator::make_rng();

    // first add 10 random digits for YYYYMMDDHH
    for (int i=0; i<10; i++) {
        x = x.random_integer(*rng, 0, 10);
        result.insert(result.end(), (char) x.to_u32bit() + 48);
    }

    // decide if we add hours/minutes/fractions
    int decision = x.random_integer(*rng, 0, 100).to_u32bit();

    if (decision > 10) {
        // add MM
        for (int i=0; i<2; i++) {
            x = x.random_integer(*rng, 0, 10);
            result.insert(result.end(), (char) x.to_u32bit() + 48);
        }

        if (decision > 40) {
            // add SS
            for (int i=0; i<2; i++) {
                x = x.random_integer(*rng, 0, 10);
                result.insert(result.end(), (char) x.to_u32bit() + 48);
            }

            if (decision > 70) {
                // add .fff
                result.insert(result.end(), '.');
                for (int i=0; i<3; i++) {
                    x = x.random_integer(*rng, 0, 10);
                    result.insert(result.end(), (char) x.to_u32bit() + 48);
                }
            }
        }
    }

    // now decide which of the 3 forms we take
    decision = x.random_integer(*rng, 0, 3).to_u32bit();
    if (decision == 0) {
        // do nothing
    }

    if (decision == 1) {
        result.insert(result.end(), 'Z');
    }

    if (decision == 2) {
        // decide if + or -
        decision = x.random_integer(*rng, 0, 2).to_u32bit();

        if (decision == 0) {
            result.insert(result.end(), '+');
        }
        else {
            result.insert(result.end(), '-');
        }

        for (int i=0; i<4; i++) {
            x = x.random_integer(*rng, 0, 10);
            result.insert(result.end(), (char) x.to_u32bit() + 48);
        }
    }
    return result;
}


void GeneralizedTimeManipulator::set_fixed_manipulations() {
    this->fixed_manipulations.push_back("910230234540Z");


    // also use general string manipulations
    vector<string> string_manipulations = this->general_fixed_string_manipulations();
    for (int i=0; i<RANDOM_STRING_MANIPULATIONS; i++) {
        string_manipulations.push_back(this->general_random_string_manipulation());
    }
    this->fixed_manipulations.insert(this->fixed_manipulations.end(), string_manipulations.begin(), string_manipulations.end());

}

void GeneralizedTimeManipulator::generate(bool random, int index) {
    if (!random) {
        if (index == -1)
            this->set_value(this->fixed_manipulations[this->manipulation_count++]);
        else
            this->set_value(this->fixed_manipulations[index]);
    }
    else {
        Botan::BigInt x;
        Botan::RandomNumberGenerator* rng = Botan::RandomNumberGenerator::make_rng();

        // do a coin toss if random time or random string will be chosen
        x = x.random_integer(*rng, 0, 2);

        if (x == 0) {
            this->set_value(general_random_string_manipulation());
        }
        else {
            this->set_value(get_random_time());
        }
    }
}

/*
http://www.obj-sys.com/asn1tutorial/node14.html

 Type GeneralizedTime takes values of the year, month, day, hour, time, minute,second, and second fraction in any of three forms.

    Local time only. ``YYYYMMDDHH[MM[SS[.fff]]]'', where the optional fff is accurate to three decimal places.
    Universal time (UTC time) only. ``YYYYMMDDHH[MM[SS[.fff]]]Z''.
    Difference between local and UTC times. ``YYYYMMDDHH[MM[SS[.fff]]]+-HHMM''.



*/
