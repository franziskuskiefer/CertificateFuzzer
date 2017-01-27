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

#include "deletionmanipulator.h"

DeletionManipulator::DeletionManipulator(shared_ptr<DERObject> obj) : Manipulator(obj) {
    this->set_fixed_manipulations();
}

void DeletionManipulator::set_fixed_manipulations() {
    size_t end_pos = this->derobj->raw_value.size();

    // don't do anything for null values
    if (end_pos == 0) {
        return;
    }
    end_pos--;


    // entries in the vectors have to be sorted in ascending order
    // AND there must not be double entries
    if (end_pos > 1) {
        this->fixed_manipulations =  {
                                    {0, end_pos/2},
                                    {0, end_pos},
                                    {0},
                                    {end_pos/2},
                                    {end_pos}
                                };
    }
    else {
        this->fixed_manipulations =  {
                                    {0},
                                    {end_pos/2},
                                    {end_pos}
                                };

    }

    // sort and remove doubles (should restore the aforementioned restrictions to the vectors)
    for (int i=0; i<this->fixed_manipulations.size(); i++) {
        sort(this->fixed_manipulations[i].begin(), this->fixed_manipulations[i].end());
        unique(this->fixed_manipulations[i].begin(), this->fixed_manipulations[i].end());
    }
  /*  cout << "fixed manipulations " << endl;
    for (vector<size_t> v : fixed_manipulations) {
        for (size_t i : v) {
            cout << i << " ";
        }
        cout << endl;
    }*/
}

size_t DeletionManipulator::get_fixed_manipulations_count()
{
    return this->fixed_manipulations.size();
}

vector<vector<size_t>> DeletionManipulator::get_fixed_manipulations() {
    return this->fixed_manipulations;
}

void DeletionManipulator::generate(bool random, int index) {
    this->restore_initial_values(); // revert last modification

    // don't delete from null values
    if (this->derobj->raw_value.size() == 0)
        return;


    if (!random) {
        if (index == -1) {
            for (size_t i=0; i<this->fixed_manipulations[this->manipulation_count].size(); i++) {

                // break if empty which can happen if the same index is deleted multiple times
                if (this->derobj->raw_value.empty())
                    break;

                // -i at the end because after the deletion of the i'th element, the index has to be adjusted by i
                this->derobj->raw_value.erase(this->derobj->raw_value.begin() + this->fixed_manipulations[this->manipulation_count][i] - i);
            }

            this->manipulation_count++;
        }
        else {
            for (size_t i=0; i<this->fixed_manipulations[index].size(); i++) {

                // break if empty which can happen if the same index is deleted multiple times
                if (this->derobj->raw_value.empty())
                    break;

                // -i at the end because after the deletion of the i'th element, the index has to be adjusted by i
                this->derobj->raw_value.erase(this->derobj->raw_value.begin() + this->fixed_manipulations[index][i] - i);
            }
        }
    }
    else {

        // choose random interval and delete
        size_t rand_range = this->derobj->raw_value.size();

        // determine the range where the bytes are deleted
        size_t pos_start = rand() % rand_range;

        size_t pos_end = rand() % rand_range;

        // swap start and end if neccessary
        if (pos_start > pos_end) {
            size_t tmp = pos_start;
            pos_start = pos_end;
            pos_end = tmp;
        }

        // delete bytes
        this->derobj->raw_value.erase(this->derobj->raw_value.begin() + pos_start, this->derobj->raw_value.begin() + pos_end);

        this->manipulation_count++;
    }
}
