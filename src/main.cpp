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


#include <fstream>
#include <vector>
#include <stack>
#include <iterator>
#include <iostream>
#include <sstream>
#include <list>
#include <math.h>
#include <time.h>
#include <memory>
#include <algorithm>
#include "DERObject.h"
#include "intmanipulator.h"
#include "oidmanipulator.h"
#include "utctimemanipulator.h"
#include "printablestringmanipulator.h"
#include "ia5stringmanipulator.h"
#include "utf8manipulator.h"
#include "insertionmanipulator.h"
#include "deletionmanipulator.h"
#include "changemanipulator.h"
#include "generalizedtimemanipulator.h"
#include "constants.h"

// botan headers for keys and signing
#include "botan/pkcs8.h"
#include "botan/rsa.h"
#include "botan/pubkey.h"

#include "base64.h"

#include <random>

// header for linux files
#include<sys/stat.h>
#include<sys/types.h>


#include <typeinfo> // for debugging
// valgrind --track-origins=yes  ./DERDEVIL

using byte = unsigned char;
using namespace std;

/**
    global pointers for convenience
*/

// root is the root of our DERObject-tree which represents the certificate
shared_ptr<DERObject> root;

// CA_issuer contains the issuer part of the certificate that corresponds to the CA
shared_ptr<DERObject> CA_issuer;

// SubjectPublicKeyInfo contains the SubjectPublicKeyInfo field which corresponds to the used private key
shared_ptr<DERObject> SubjectPublicKeyInfo;

// global LogFile to log the manipulations for each certificate
ofstream LogFile;

// tracks the file number for creating the appropriate file name
size_t file_number = 0;

// only used for output to recognize if we have outputted the cert number for the current 1000 block of certs
size_t file_number_100 = 0;

// maximum number of certificates that will be created
size_t MAX_CERTS;

bool SIGN_CERTS = true;

bool CREATE_TEST_CERT = false;

string SET_COMMONNAME;

// FIXME: feed from libfuzzer
unsigned int seed;


/**
    Reads a file into a byte vector
*/
static vector<byte> read_bytes(char const* filename) {
    ifstream ifs(filename, ios::binary|ios::ate);
    ifstream::pos_type pos = ifs.tellg();

    // Certificate in the path specified by filename does not exist
    if (pos == -1) {
        cout << "File not found" << endl;
        exit(0);
    }

    vector<char>  result(pos);

    ifs.seekg(0, ios::beg);
    ifs.read(&result[0], pos);


    vector<byte> result2;
    for (char c : result) {
        result2.push_back((byte)c);
    }

    return result2;
}


/**
    prints hexdump of the root node
*/
void print_hexdump() {
    vector<byte> result = root->raw_bytes();
    cout << endl;
    for (byte b : result) {
        if (int(b) < 16)
            cout << "0";
        cout << hex << int(b) << " ";
    }
    cout << dec << endl << endl;
}


/**
    prints a visual representation of a given DERObject node
*/
void print_tree(shared_ptr<DERObject> node, int depth=0) {
    for (int i=0; i<depth; i++) {
        cout << "   ";
    }
    if (!node->name.empty())
        cout << node->name << " ";
    if ((int(node->raw_tag) & 192) != 0) { // tagged
        if (node->is_constructed()) {
            cout << "EXPLICIT";
        }
        else {
            cout << "IMPLICIT";
        }
        cout << " [" << (int(node->raw_tag) & 31) << "]";
    }
    else {
        cout << mapTags[(int(node->raw_tag) & 31)];
    }
    cout << " (" << DERObject::raw_length_to_int(node->raw_length) << ")" << endl;

    for (shared_ptr<DERObject> child : node->children) {
        print_tree(child, depth+1);
    }
}

/**
    Sets the subject public key info in the certificate corresponding to the local private key
    requires to call get_public_key_from_file once before


*/
void set_SubjectPublicKeyInfo() {
    // find out which child in TBSCertificate is subjectPublicKeyInfo to override
    for (int i=0; i<root->get_object_by_name("TBSCertificate")->children.size(); i++) {
        if (root->get_object_by_name("TBSCertificate")->children[i]->name.compare("subjectPublicKeyInfo") == 0) {
            root->get_object_by_name("TBSCertificate")->children[i] = SubjectPublicKeyInfo;
            break;
        }
    }
}


/**
    sets the issuer in the certificate
    issuer is supposed to be a DERObject that represents a valid issuer value

*/
void set_issuer(shared_ptr<DERObject> issuer) {
    // find out which child in TBSCertificate is issuer to override
    for (int i=0; i<root->get_object_by_name("TBSCertificate")->children.size(); i++) {
        if (root->get_object_by_name("TBSCertificate")->children[i]->name.compare("issuer") == 0) {
            root->get_object_by_name("TBSCertificate")->children[i] = CA_issuer;
            break;
        }
    }
}

/**
    sets the CA issuer field in the certificate
*/
void set_CA_issuer() {
    shared_ptr<DERObject> derobj1, derobj2, derobj3;
    vector<int> oid;
    string str;

    CA_issuer = shared_ptr<DERObject>(new DERObject);
    CA_issuer->raw_tag = 48;
    CA_issuer->name = "issuer";

    // first SET
    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = ASN1_TYPE_SET + 32; // + 32 for constructed bit
    CA_issuer->children.push_back(derobj1);

        // SEQUENCE
        derobj2 = shared_ptr<DERObject>(new DERObject);
        derobj2->raw_tag = ASN1_TYPE_SEQUENCE + 32; // + 32 for constructed bit
        derobj1->children.push_back(derobj2);

            // OID
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_OBJECT_IDENTIFIER;
            derobj2->children.push_back(derobj3);

            oid = { 2, 5, 4, 6 };
            OIDManipulator m1 = OIDManipulator(derobj3);
            m1.set_value(oid);

            // PrintableString
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_PRINTABLESTRING;
            derobj2->children.push_back(derobj3);

            str = "CA";
            PrintableStringManipulator m2 = PrintableStringManipulator(derobj3);
            m2.set_value(str);

    // second SET
    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = ASN1_TYPE_SET + 32; // + 32 for constructed bit
    CA_issuer->children.push_back(derobj1);

        // SEQUENCE
        derobj2 = shared_ptr<DERObject>(new DERObject);
        derobj2->raw_tag = ASN1_TYPE_SEQUENCE + 32; // + 32 for constructed bit
        derobj1->children.push_back(derobj2);

            // OID
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_OBJECT_IDENTIFIER;
            derobj2->children.push_back(derobj3);

            oid = { 2, 5, 4, 8 };
            OIDManipulator m3 = OIDManipulator(derobj3);
            m3.set_value(oid);

            // UTF8String
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_UTF8STRING;
            derobj2->children.push_back(derobj3);

            str = "CA";
            UTF8StringManipulator m4 = UTF8StringManipulator(derobj3);
            m4.set_value(str);


    // third SET
    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = ASN1_TYPE_SET + 32; // + 32 for constructed bit
    CA_issuer->children.push_back(derobj1);

        // SEQUENCE
        derobj2 = shared_ptr<DERObject>(new DERObject);
        derobj2->raw_tag = ASN1_TYPE_SEQUENCE + 32; // + 32 for constructed bit
        derobj1->children.push_back(derobj2);

            // OID
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_OBJECT_IDENTIFIER;
            derobj2->children.push_back(derobj3);

            oid = { 2, 5, 4, 7 };
            OIDManipulator m5 = OIDManipulator(derobj3);
            m5.set_value(oid);

            // UTF8String
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_UTF8STRING;
            derobj2->children.push_back(derobj3);

            str = "CA";
            UTF8StringManipulator m6 = UTF8StringManipulator(derobj3);
            m6.set_value(str);

    // fourth SET
    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = ASN1_TYPE_SET + 32; // + 32 for constructed bit
    CA_issuer->children.push_back(derobj1);

        // SEQUENCE
        derobj2 = shared_ptr<DERObject>(new DERObject);
        derobj2->raw_tag = ASN1_TYPE_SEQUENCE + 32; // + 32 for constructed bit
        derobj1->children.push_back(derobj2);

            // OID
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_OBJECT_IDENTIFIER;
            derobj2->children.push_back(derobj3);

            oid = { 2, 5, 4, 10 };
            OIDManipulator m7 = OIDManipulator(derobj3);
            m7.set_value(oid);

            // UTF8String
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_UTF8STRING;
            derobj2->children.push_back(derobj3);

            str = "CA";
            UTF8StringManipulator m8 = UTF8StringManipulator(derobj3);
            m8.set_value(str);


    // fifth SET
    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = ASN1_TYPE_SET + 32; // + 32 for constructed bit
    CA_issuer->children.push_back(derobj1);

        // SEQUENCE
        derobj2 = shared_ptr<DERObject>(new DERObject);
        derobj2->raw_tag = ASN1_TYPE_SEQUENCE + 32; // + 32 for constructed bit
        derobj1->children.push_back(derobj2);

            // OID
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_OBJECT_IDENTIFIER;
            derobj2->children.push_back(derobj3);

            oid = { 2, 5, 4, 11 };
            OIDManipulator m9 = OIDManipulator(derobj3);
            m9.set_value(oid);

            // UTF8String
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_UTF8STRING;
            derobj2->children.push_back(derobj3);

            str = "CA";
            UTF8StringManipulator m10 = UTF8StringManipulator(derobj3);
            m10.set_value(str);


    // sixth SET
    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = ASN1_TYPE_SET + 32; // + 32 for constructed bit
    CA_issuer->children.push_back(derobj1);

        // SEQUENCE
        derobj2 = shared_ptr<DERObject>(new DERObject);
        derobj2->raw_tag = ASN1_TYPE_SEQUENCE + 32; // + 32 for constructed bit
        derobj1->children.push_back(derobj2);

            // OID
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_OBJECT_IDENTIFIER;
            derobj2->children.push_back(derobj3);

            oid = { 2, 5, 4, 3 };
            OIDManipulator m11 = OIDManipulator(derobj3);
            m11.set_value(oid);

            // UTF8String
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_UTF8STRING;
            derobj2->children.push_back(derobj3);

            str = "localhost";
            UTF8StringManipulator m12 = UTF8StringManipulator(derobj3);
            m12.set_value(str);


    // seventh SET
    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = ASN1_TYPE_SET + 32; // + 32 for constructed bit
    CA_issuer->children.push_back(derobj1);

        // SEQUENCE
        derobj2 = shared_ptr<DERObject>(new DERObject);
        derobj2->raw_tag = ASN1_TYPE_SEQUENCE + 32; // + 32 for constructed bit
        derobj1->children.push_back(derobj2);

            // OID
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_OBJECT_IDENTIFIER;
            derobj2->children.push_back(derobj3);

            oid = { 1, 2, 840, 113549, 1, 9, 1 };
            OIDManipulator m13 = OIDManipulator(derobj3);
            m13.set_value(oid);

            // IA5String
            derobj3 = shared_ptr<DERObject>(new DERObject);
            derobj3->raw_tag = ASN1_TYPE_IA5STRING;
            derobj2->children.push_back(derobj3);

            str = "CA";
            IA5StringManipulator m14 = IA5StringManipulator(derobj3);
            m14.set_value(str);
}



/**
    Method that calculates a valid signature in respect of the specified key in CA_KEY_PATH
    Creates Sha256WithRSAEncryption Signature
*/
void sign_certificate() {
    // signature algorithm OID should be "1.2.840.113549.1.1.11"
    vector<int> oid = {1, 2, 840, 113549, 1, 1, 11 };

    OIDManipulator o = OIDManipulator(root->get_object_by_name("signatureAlgorithm"));
    o.set_value(oid);


    OIDManipulator o2 = OIDManipulator(root->get_object_by_name("signature2Algorithm"));
    o2.set_value(oid);

    root->recalculate_lengths();

    // Private_Key *PKCS8::load_key(const std::string &filename, RandomNumberGenerator &rng, const std::string &passphrase = "")
    Botan::Private_Key* priv = Botan::PKCS8::load_key(CA_KEY_PATH, *Botan::RandomNumberGenerator::make_rng(), "");

    //Botan::RSA_PrivateKey* priv_rsa = dynamic_cast<Botan::RSA_PrivateKey*> (priv);
    /*cout << endl << "d: " << priv_rsa->get_d() << endl;
    cout << endl << "n: " << priv_rsa->get_n() << endl;
    cout << endl << "n length: " << priv_rsa->get_n().bytes() << endl;*/

    Botan::PK_Signer signer = Botan::PK_Signer(*priv, "EMSA3(SHA-256)");

    // sign TBSCertificate part
    vector<byte> signature = signer.sign_message(root->get_object_by_name("TBSCertificate")->raw_bytes(), *Botan::RandomNumberGenerator::make_rng());

    // replace signature
    root->get_object_by_name("signatureValue")->raw_value = signature;
    root->get_object_by_name("signatureValue")->raw_value.insert(root->get_object_by_name("signatureValue")->raw_value.begin(), 0);
    root->recalculate_lengths();

    // free the memory
    delete priv;
}


/**
    writes our certificate-tree with root 'root' in DER-encoding to a file
*/
int write_der_file(vector<byte> cert_content, bool cert_signed) {
    stringstream ss;
    ss << file_number;
    string open_file;

    if (cert_signed) {
        open_file = (FUZZED_CERTS_FOLDER_NAME + string("/correctly_signed/" + FUZZED_CERTS_PREFIX) + ss.str() + ".der");
    }
    else {
        open_file = (FUZZED_CERTS_FOLDER_NAME + string("/incorrectly_signed/" + FUZZED_CERTS_PREFIX) + ss.str() + ".der");
    }

    // special case for creating a test certificate
    if (CREATE_TEST_CERT) {
        open_file = (FUZZED_CERTS_FOLDER_NAME + string("/test/" + FUZZED_CERTS_PREFIX) + "test" + ".der");
    }

    ofstream write(open_file);

    if (write.is_open()) {
        for (byte b : cert_content)
            write << b;
        write.close();
        file_number++;
        return 0;
    }
    else {
        cout << "Unable to open file";
        return -1;
    }
}

/**
    writes our certificate-tree with root 'root' in PEM-encoding to a file
*/
int write_pem_file(vector<byte> cert_content, bool cert_signed) {
    byte arr[cert_content.size()];
    copy(cert_content.begin(), cert_content.end(), arr);

    stringstream ss;
    ss << file_number;
    string open_file;
    if (cert_signed) {
        open_file = (FUZZED_CERTS_FOLDER_NAME + string("/correctly_signed/" + FUZZED_CERTS_PREFIX) + ss.str() + ".pem");
    }
    else {
        open_file = (FUZZED_CERTS_FOLDER_NAME + string("/incorrectly_signed/" + FUZZED_CERTS_PREFIX) + ss.str() + ".pem");
    }

    // special case for creating a test certificate
    if (CREATE_TEST_CERT) {
        open_file = (FUZZED_CERTS_FOLDER_NAME + string("/test/" + FUZZED_CERTS_PREFIX) + "test" + ".pem");
    }

    ofstream write(open_file);

    if (write.is_open()) {
        write << "-----BEGIN CERTIFICATE-----\n";
        int count_to_64 = 0;
        for (byte c : base64_encode(arr, cert_content.size())) {
            write << c;
            if (count_to_64 == 63) {
                write << "\n";
                count_to_64 = 0;
            }
            else
                count_to_64++;
        }
        write << "\n-----END CERTIFICATE-----\n";
        write.close();
        file_number++;
        return 0;
    }
    else {
        cout << "Unable to open file" << endl;
        cout << open_file;
        return -1;
    }
}

/**
    flips random bits in the DER-encoding and saves the file after each bitflip.
    Does not revert the bitflips in the DERObject-Tree
*/
void do_bitflips(size_t quantity, size_t max_chunk_size) {
    LogFile << "Flipping " << quantity << " bits with max_chunk_size " << max_chunk_size << "\n";

    sign_certificate();

    // Botan::RandomNumberGenerator *rng = Botan::RandomNumberGenerator::make_rng();
    // Botan::BigInt x;

    vector<byte> cert_content = root->raw_bytes();

    size_t flip_byte;
    size_t flip_bit;
    size_t chunk_size;

    std::mt19937 rng(seed);
    for (size_t i=0; i<quantity; i++) {
        // flip_byte = x.random_integer(*rng, 0, cert_content.size()-1).to_u32bit();
        // flip_bit = x.random_integer(*rng, 0, 7).to_u32bit();
        // chunk_size = x.random_integer(*rng, 1, max_chunk_size).to_u32bit();
        std::uniform_int_distribution<size_t> dist(0, cert_content.size()-1);
        flip_byte = dist(rng);
        dist = std::uniform_int_distribution<size_t>(0, 7);
        flip_bit = dist(rng);
        dist = std::uniform_int_distribution<size_t>(0, max_chunk_size);
        chunk_size = dist(rng);

        for (size_t j=0; j<chunk_size; j++) {
            if (flip_bit+j > 7) {
                // go into next byte
                flip_bit = 0;
                flip_byte++;

                // don't go on if we already were in the last byte
                if (flip_byte > cert_content.size()-1)
                    break;
            }
            cert_content[flip_byte] ^= 1 << flip_bit+j;
        }

        // write certificate to file
        LogFile << file_number << " flip bits\n";
        write_pem_file(cert_content, false);
    }
}


/**
    fuzzes all fields in the vector cert_field_vector
*/
void fuzz_engine_single_field(vector<shared_ptr<DERObject>> cert_field_vector) {

    LogFile << "fuzzing single fields\n\n";
    stringstream LogFileStr;

    for (shared_ptr<DERObject> field: cert_field_vector) {
        // Create the 3 "general manipulators" which are used for every field as they are not dependend on the type of the field
        shared_ptr<Manipulator> x, im, dm, cm;
        im = shared_ptr<Manipulator>(new InsertionManipulator(field));
        dm = shared_ptr<Manipulator>(new DeletionManipulator(field));
        cm = shared_ptr<Manipulator>(new ChangeManipulator(field));

        vector<shared_ptr<Manipulator>> manipulators;

        // factory call to create the field-specific manipulator
        x = Manipulator::make_manipulator(field);
        if (x != nullptr)
            manipulators.push_back(x);

        // add "general manipulators"
        manipulators.push_back(im);
        manipulators.push_back(dm);
        manipulators.push_back(cm);

        size_t RANDOM_MANIPULATIONS_COUNT = 30;

        // iterate over all manipulators to manipulate the field
        for (shared_ptr<Manipulator> manipulator : manipulators) {
            for (int i=0; i < (manipulator->get_fixed_manipulations_count() + RANDOM_MANIPULATIONS_COUNT); i++) {
                if (file_number >= MAX_CERTS && MAX_CERTS > 0) {
                    return;
                }



                // restore initial values before modifying the value
                manipulator->restore_initial_values();

                // do fixed or random manipulations
                if (i < manipulator->get_fixed_manipulations_count()) {
                    manipulator->generate(false);
                    LogFileStr << typeid(*manipulator).name() << "(fixed)";
                }
                else {
                    manipulator->generate(true);
                    LogFileStr << typeid(*manipulator).name() << "(random)";
                }

                // recalculate the length information in the certificate-tree for correct DER encoding
                root->recalculate_lengths();

                // write certificate to file
                LogFile << file_number << " " << LogFileStr.str() << "(wrong sig)\n";
                write_pem_file(root->raw_bytes(), false);
                //write_der_file(file_number, root->raw_bytes());


                if (SIGN_CERTS) {
                    // create correct signature
                    sign_certificate();

                    // write certificate to file again, this time with correct signature
                    LogFile << file_number << " " << LogFileStr.str() << "(correct sig)\n";
                    write_pem_file(root->raw_bytes(), true);
                    //write_der_file(file_number, root->raw_bytes());
                }


                LogFileStr.str( std::string() );
                LogFileStr.clear();

                // now do some bit flips
                do_bitflips(10, 8);
                // some output on the screen
                if (file_number - file_number_100 >= 100) {
                    cout << "fuzz_engine_single_field at cert " << file_number << endl;
                    file_number_100 = file_number;
                }
            }

            // restore state that our tree had before applying manipulations of 'manipulator'
            manipulator->restore_initial_values();
            root->recalculate_lengths();
        }
    }
}


/**
    fuzzes multiple fields simultaniously

    cert_field_vector:                  vector that contains all fields of the certificate tree
    num_fields:                         number of fields that will be fuzzed simultaniously
    num_iterations:                     number of how many different field "sets" will be fuzzed
    num_manipulations_per_iteration:    number of manipulations that will be applied to the fields in one iteration
*/
void fuzz_engine_multiple_fields(vector<shared_ptr<DERObject>> cert_field_vector, size_t num_fields, size_t num_iterations, size_t num_manipulations_per_iteration) {

    LogFile << "fuzzing " << num_fields << " fields with " << num_iterations << " iterations and " << num_manipulations_per_iteration << " manipulations per iteration\n\n";
    stringstream LogFileStr;

    // can't do this
    if (num_fields > cert_field_vector.size()) {
        return;
    }

    // Botan::BigInt x;
    size_t x;
    vector<size_t> fuzz_fields;
    vector<shared_ptr<DERObject>> fuzz_objects;
    vector<vector<shared_ptr<Manipulator>>> manipulators;
    vector<shared_ptr<Manipulator>> manipulator;
    shared_ptr<Manipulator> sm, im, dm, cm;
    // Botan::RandomNumberGenerator *rng = Botan::RandomNumberGenerator::make_rng();
    std::mt19937 rng(seed);

    for (size_t iteration = 0; iteration < num_iterations; iteration++) {
        fuzz_fields.clear();
        fuzz_objects.clear();
        manipulators.clear();

        LogFile << "Iteration " << iteration << "\n";

        // add first integer to fuzz_fields
        // x = x.random_integer(*rng, 0, cert_field_vector.size()-1);
        // fuzz_fields.push_back(x.to_u32bit());
        std::uniform_int_distribution<size_t> dist(0, cert_field_vector.size()-1);
        fuzz_fields.push_back(dist(rng));

        LogFile << "fields: " << x;

        // fill fuzz_fields with distinct integers
        for (size_t i=0; i<num_fields-1; i++) {
            // x = x.random_integer(*rng, 0, cert_field_vector.size()-1);
            dist = std::uniform_int_distribution<size_t>(0, cert_field_vector.size()-1);
            x = dist(rng);
            while (std::find(fuzz_fields.begin(), fuzz_fields.end(), x) != fuzz_fields.end()) {
                // x = x.random_integer(*rng, 0, cert_field_vector.size()-1);
                dist = std::uniform_int_distribution<size_t>(0, cert_field_vector.size()-1);
                x = dist(rng);
            }
            fuzz_fields.push_back(x);
            LogFile << ", " << x;
        }
        LogFile << "\n";

        // fill fuzz_objects vector which contains all objects that shall be fuzzed
        for (size_t i=0; i<fuzz_fields.size(); i++) {
            fuzz_objects.push_back(cert_field_vector[fuzz_fields[i]]);
        }

        // iterate over fuzz_objects vector and create all manipulators for the fields
        for (size_t i=0; i<fuzz_objects.size(); i++) {
            manipulators.push_back(vector<shared_ptr<Manipulator>>());

            im = shared_ptr<Manipulator>(new InsertionManipulator(fuzz_objects[i]));
            dm = shared_ptr<Manipulator>(new DeletionManipulator(fuzz_objects[i]));
            cm = shared_ptr<Manipulator>(new ChangeManipulator(fuzz_objects[i]));

            // factory call to create the field-specific manipulator
            sm = Manipulator::make_manipulator(fuzz_objects[i]);
            if (sm != nullptr)
                manipulators[i].push_back(sm);

            manipulators[i].push_back(im);
            manipulators[i].push_back(dm);
            manipulators[i].push_back(cm);
        }

        // fuzz all fields now
        for (int manipulation_count=0; manipulation_count<num_manipulations_per_iteration; manipulation_count++) {
            manipulator.clear();

            for (size_t i=0; i<fuzz_objects.size(); i++) {
                // first choose which manipulator will be taken for this field
                // x = x.random_integer(*rng, 1, 100);
                dist = std::uniform_int_distribution<size_t>(1, 100);
                x = dist(rng);
                // if specific manipulator exists for this field
                if (manipulators[i].size() == 4) {
                     // choose specific manipulator in 40% of cases and the general manipulators in 20% each
                    if (x <= 40)
                        manipulator.push_back(manipulators[i][0]);
                    else if (x <= 60)
                        manipulator.push_back(manipulators[i][1]);
                    else if (x <= 80)
                        manipulator.push_back(manipulators[i][2]);
                    else
                        manipulator.push_back(manipulators[i][3]);
                }
                // only general manipulators to choose from
                else {
                    if (x <= 33)
                        manipulator.push_back(manipulators[i][0]);
                    else if (x <= 66)
                        manipulator.push_back(manipulators[i][1]);
                    else
                        manipulator.push_back(manipulators[i][2]);
                }

                // now choose (sample) if random or fixed value will be chosen.
                // x = x.random_integer(*rng, 1, 100);
                x = dist(rng);
                if (x <= 75 and manipulator[i]->get_fixed_manipulations_count() > 0) {
                    // int index = x.random_integer(*rng, 0, manipulator[i]->get_fixed_manipulations_count()-1).to_u32bit();
                    dist = std::uniform_int_distribution<size_t>(0, manipulator[i]->get_fixed_manipulations_count()-1);
                    int index = dist(rng);
                    manipulator[i]->generate(false, index);
                    LogFileStr << typeid(*manipulator[i]).name() << " (fixed)  ||  ";
                }
                else {
                    manipulator[i]->generate(true);
                    LogFileStr << typeid(*manipulator[i]).name() << " (random)  ||  ";
                }
            }

            // now save files
            // recalculate the length information in the certificate-tree for correct DER encoding
            root->recalculate_lengths();


            if (file_number >= MAX_CERTS && MAX_CERTS > 0)  {
                return;
            }

            // write certificate to file
            LogFile << file_number << " " << LogFileStr.str() << "(wrong sig)\n";
            write_pem_file(root->raw_bytes(), false);

            if (SIGN_CERTS) {
                // create correct signature
                sign_certificate();

                // write certificate to file again, this time with correct signature
                LogFile << file_number << " " << LogFileStr.str() << "(correct sig)\n";
                write_pem_file(root->raw_bytes(), true);
            }

            LogFileStr.str( std::string() );
            LogFileStr.clear();

            // some output on the screen
            if (file_number - file_number_100 >= 100) {
                    cout << "fuzz_engine_multiple_fields at cert " << file_number << endl;
                    file_number_100 = file_number;
                }

            // restore state that our tree had before applying manipulations
            for (shared_ptr<Manipulator> m : manipulator) {
                m->restore_initial_values();
                root->recalculate_lengths();
            }
        }
        LogFile << "\n";
    }
}


/**
    creates a vector of certificate fields of for easier iteration (no recursion needed)
*/
vector<shared_ptr<DERObject>> make_cert_field_vector(shared_ptr<DERObject> node) {
    vector<shared_ptr<DERObject>>  certificate_field_vector;

    if (!node->is_constructed()) {
        certificate_field_vector.push_back(node);
    }
    else {
        vector<shared_ptr<DERObject>> tmp;
        for (shared_ptr<DERObject> child : node->children) {
            tmp = make_cert_field_vector(child);
            certificate_field_vector.insert(certificate_field_vector.end(), tmp.begin(), tmp.end());
        }
    }
    return certificate_field_vector;
}



// expects a X.509 certificate in valid DER encoding
// expand_primitives_flag: when set to true it will expand BIT STRINGS and OCTET STRINGS in the x509 certificate where ASN.1 structures are expected
// assign_x509_names: when set to true it will assign names to the x509 certificate parts. should be set to zero if not a complete x509 certificate is read
// expect_public_key: when this method is used to only read in the public key, this should be true
shared_ptr<DERObject> parse_DER(vector<byte> input, bool expand_primitives_flag=true, bool assign_x509_names = true, bool expect_public_key = false) {

    bool pseudo_constructed;
    shared_ptr<DERObject> root_node;


	bool iterate;
    size_t index = 0;
	byte current_byte;
	size_t read_octets_left, depth;

    // Finite State machine to remember at which part of the certificate we are to properly name the parts
	enum STATE { STATE_start, STATE_TBSCertificate, STATE_version, STATE_in_version, STATE_serial, STATE_signature, STATE_signatureAlgorithm, STATE_signatureParameters, STATE_issuer,
                    STATE_in_issuer, STATE_validity, STATE_notBefore, STATE_notAfter, STATE_subject, STATE_in_subject, STATE_subjectPublicKeyInfo,
                    STATE_subjectPublicKeyInfoAlgorithmSequence, STATE_subjectPublicKeyInfoAlgorithm, STATE_subjectPublicKeyInfoParameters, STATE_subjectPublicKey, STATE_in_subjectPublicKey,
                    STATE_issuerUniqueID, STATE_subjectUniqueID, STATE_extensions, STATE_in_extensions, STATE_signature2, STATE_signature2Algorithm,
                    STATE_signature2Parameters, STATE_signatureValue, STATE_finished };
	string name;
	STATE name_state = STATE_start;
	size_t depth_before;



	// the stack is used to obtain the parent of the currently parsed entry
	stack<shared_ptr<DERObject>> curr_top;

    // the DERObject that is worked on in the loop
	shared_ptr<DERObject> derobj;

	// std::runtime_error("message")

	bool finished = false;
	while (!finished) {
        // if only root exists yet
        if (curr_top.empty()) {
            root_node = shared_ptr<DERObject>(new DERObject);
            derobj = root_node;
            derobj->root = true;
        }
        else {
            derobj = shared_ptr<DERObject>(new DERObject);
        }

        // remember start position
        derobj->pos = index;http://lapo.it/asn1js/#308204CD30820436A00302010202100C009310D206DBE337553580118DDC87300D06092A864886F70D01010B05003068310B3009060355040613024341310B300906035504080C024341310B300906035504070C024341310B3009060355040A0C024341310B3009060355040B0C0243413112301006035504030C096C6F63616C686F73743111300F06092A864886F70D01090116024341301E170D3134303430383030303030305A170D3136303431323132303030305A3081EF311D301B060355040F0C1450726976617465204F7267616E697A6174696F6E31133011060B2B0601040182373C0201031302555331193017060B2B0601040182373C020102130844656C61776172653110300E0603550405130735313537353530311730150603550409130E3534382034746820537472656574310E300C060355041113053934313037310B3009060355040613025553311330110603550408130A43616C69666F726E6961311630140603550407130D53616E204672616E636973636F31153013060355040A130C4769744875622C20496E632E31123010060355040313096C6F63616C686F737430819F300D06092A864886F70D010101050003818D0030818902818100F75577DB15BE264441F0C18C3BE90BB92EF96D695D648AD552C18BF6499B6FEFD7E95022ECA23FF29698C4E811580F965116F571D7831A3868490C7CB40B5488BE404670C77ED97DED9A563A5CA9ABB9A5B3F421BDAE306E8B07AB5DCA8B24C07CAC833CA15DC705BB1BE2C0D1A0BDCA0975909281751371C2F703095B96AFD10203010001A38201EE308201EA301F0603551D230418301680143DD350A5D6A0ADEEF34A600A65D321D4F8F8D60F301D0603551D0E041604146A43907D3B98147252953AAA280A43F8517ED3A630250603551D11041E301C820A6769746875622E636F6D820E7777772E6769746875622E636F6D300E0603551D0F0101FF0404030205A0301D0603551D250416301406082B0601050507030106082B0601050507030230750603551D1F046E306C3034A032A030862E687474703A2F2F63726C332E64696769636572742E636F6D2F736861322D65762D7365727665722D67312E63726C3034A032A030862E687474703A2F2F63726C342E64696769636572742E636F6D2F736861322D65762D7365727665722D67312E63726C30420603551D20043B3039303706096086480186FD6C0201302A302806082B06010505070201161C68747470733A2F2F7777772E64696769636572742E636F6D2F43505330818806082B06010505070101047C307A302406082B060105050730018618687474703A2F2F6F6373702E64696769636572742E636F6D305206082B060105050730028646687474703A2F2F636163657274732E64696769636572742E636F6D2F446967694365727453484132457874656E64656456616C69646174696F6E53657276657243412E637274300C0603551D130101FF04023000300D06092A864886F70D01010B0500038181001AD043F7DCCFF55B6A3EF9007B98AB873E94C5F383FC89DF890F587C489B78C5E049388B77E20309CE864503FDEAF0BF2DA002C8AAE60F0B7C31A1F52488ECA971A11647EB584DF1DE22BC997B3BECF0C94342C0BF429E4F71823E18E162E7BEF61431FC409EC52D9284F4C0447DF9C96FFE4DDD8BFA6916D450AF37079D632D


        if (!curr_top.empty()) {
            // if the index is >= the closing point of the top-node (squence or set), pop it
            iterate = true;
            while (iterate) {
                iterate = false;
                if (curr_top.top()->pos + DERObject::raw_length_to_int(curr_top.top()->raw_length) + curr_top.top()->raw_length.size() + 1 <= index) {    // + 1 for tag byte
                    if (!curr_top.top()->root) { // don't pop root node
                        curr_top.pop();
                        iterate = true;
                    }
                }
            }

            // make derobj child of the current top object
            derobj->parent = curr_top.top();

            // add as child to parent node
            curr_top.top()->children.push_back(derobj);
        }
        else {
            curr_top.push(derobj); // push root
        }


		current_byte = input.at(index++);

        /** read tag */
        derobj->raw_tag = current_byte;
		// constructed (bit 6 == 1), push object to stack
		if (derobj->is_constructed() && !derobj->root) {
            curr_top.push(derobj);
		}

        depth = curr_top.size() - 1;
        if (!derobj->is_constructed())
            depth++;




        if (assign_x509_names) {
            switch (name_state) {
                case STATE_start :
                    name = "Certificate";
                    name_state = STATE_TBSCertificate;
                    break;

                case STATE_TBSCertificate :
                    name = "TBSCertificate";
                    name_state = STATE_version;
                    break;

                case STATE_in_version :
                    name_state = STATE_serial;
                    break;

                case STATE_version :
                    if (int(derobj->raw_tag) == 160) {
                        name = "version";
                        name_state = STATE_in_version;
                        break;
                    }
                    // version is optional and is skipped in this case
                    else {
                        name_state = STATE_serial;
                    }

                case STATE_serial :
                    name = "serialNumber";
                    name_state = STATE_signature;
                    break;

                case STATE_signature :
                    name = "signature";
                    name_state = STATE_signatureAlgorithm;
                    break;

                case STATE_signatureAlgorithm :
                    name = "signatureAlgorithm";
                    name_state = STATE_signatureParameters;
                    break;

                case STATE_signatureParameters :
                    if (depth == depth_before) {
                        name = "signatureParameters";
                        break;
                    }
                    else {
                        name_state = STATE_issuer;
                    }

                case STATE_issuer :
                    name = "issuer";
                    name_state = STATE_in_issuer;
                    break;

                case STATE_in_issuer :
                    if (depth == 2) {
                        name_state = STATE_validity;
                    }
                    else {
                        break;
                    }

                case STATE_validity :
                    name = "validity";
                    name_state = STATE_notBefore;
                    break;

                case STATE_notBefore :
                    name = "notBefore";
                    name_state = STATE_notAfter;
                    break;

                case STATE_notAfter :
                    name = "notAfter";
                    name_state = STATE_subject;
                    break;

                case STATE_subject :
                    name = "subject";
                    name_state = STATE_in_subject;
                    break;

                case STATE_in_subject :
                    if (depth == 2) {
                        name_state = STATE_subjectPublicKeyInfo;
                    }
                    else {
                        break;
                    }

                case STATE_subjectPublicKeyInfo :
                    name = "subjectPublicKeyInfo";
                    name_state = STATE_subjectPublicKeyInfoAlgorithmSequence;
                    break;

                case STATE_subjectPublicKeyInfoAlgorithmSequence :
                    name = "subjectPublicKeyInfoAlgorithmSequence";
                    name_state = STATE_subjectPublicKeyInfoAlgorithm;
                    break;

                case STATE_subjectPublicKeyInfoAlgorithm :
                    name = "subjectPublicKeyInfoAlgorithm";
                    name_state = STATE_subjectPublicKeyInfoParameters;
                    break;

                case STATE_subjectPublicKeyInfoParameters :
                    if (depth == depth_before) {
                        name = "subjectPublicKeyParameters";
                        name_state = STATE_subjectPublicKey;
                        break;
                    }
                    else {
                        name_state = STATE_subjectPublicKey;
                    }


                case STATE_subjectPublicKey :
                    name = "subjectPublicKey";
                    name_state = STATE_in_subjectPublicKey;
                    break;

                case STATE_in_subjectPublicKey :
                    if (depth == 2) {
                        name_state = STATE_issuerUniqueID;
                    }
                    // if extensions and subjectUniqueID don't exist next tag will be at depth 1
                    else if (depth == 1) {
                        name_state = STATE_signature2;
                    }
                    else {
                        break;
                    }


                case STATE_issuerUniqueID :
                    if (int(derobj->raw_tag) == 129) {
                        name = "issuerUniqueID";
                        name_state = STATE_subjectUniqueID;
                        break;
                    }
                    else {
                        name_state = STATE_subjectUniqueID;
                    }

                case STATE_subjectUniqueID :
                    if (int(derobj->raw_tag) == 130) {
                        name = "subjectUniqueID";
                        name_state = STATE_extensions;
                        break;
                    }
                    else {
                        name_state = STATE_extensions;
                    }

                case STATE_extensions :
                    if (int(derobj->raw_tag) == 163) {
                        name = "extensions";
                        name_state = STATE_in_extensions;
                        break;
                    }
                    else {
                        name_state = STATE_signature2;
                    }

                case STATE_in_extensions :
                    if (name_state == STATE_in_extensions) {
                        if (depth == 1) {
                            name_state = STATE_signature2;
                        }
                        else {
                            break;
                        }
                    }


                case STATE_signature2 :
                    name = "signature2";
                    name_state = STATE_signature2Algorithm;
                    break;

                case STATE_signature2Algorithm :
                    name = "signature2Algorithm";
                    name_state = STATE_signature2Parameters;
                    break;

                case STATE_signature2Parameters :
                    if (depth == depth_before) {
                        name = "signature2Parameters";
                        name_state = STATE_signatureValue;
                        break;
                    }
                    else {
                        name_state = STATE_signatureValue;
                    }

                case STATE_signatureValue :
                    name = "signatureValue";
                    name_state = STATE_finished;
                    break;

                default :
                    name = "none";
            }
            if (name != "none") {
                derobj->name = name;
            }
            name = "none";
            depth_before = depth;
        }

        // logic for expanding primitives if they contain more ASN1 data
        if (expand_primitives_flag) {
            pseudo_constructed = false;
            if (curr_top.size() > 3) {
                if ((derobj->parent->parent->parent->name.compare("extensions") == 0 and int(derobj->raw_tag) == 4) )
                    pseudo_constructed = true;
            }

            if (derobj->name.compare("subjectPublicKey") == 0) {
                pseudo_constructed = true;
            }

            // in the public key sequence there will be exactly one BIT STRING and this one has to be expanded
            if (expect_public_key && int(derobj->raw_tag) == ASN1_TYPE_BIT_STRING) {
                pseudo_constructed = true;
            }


            if (pseudo_constructed) {
                derobj->pseudo_constructed = true;
                curr_top.push(derobj); // push to stack as would do with a real constructed type
            }
        }



        /** read length */
        current_byte = input.at(index++);
        derobj->raw_length.push_back(current_byte);

        if (int(current_byte) <= 127) {
            read_octets_left = 0;
        }
        else {
            read_octets_left = int(current_byte) - 128;
        }
        if (read_octets_left > 0) {
            for (int i=read_octets_left-1; i>=0; i--) {
                current_byte = input.at(index++);
                derobj->raw_length.push_back(current_byte);
            }
        }

        // for pseudo_constructed BIT STRING ignore the first byte because it's zero (unused bits) instead of the first TLV
        if (derobj->pseudo_constructed and int(derobj->raw_tag) == 3)
            index++;


        /** read data but only if not constructed type */
        if (!derobj->is_constructed()) {
            for (int i=0; i<DERObject::raw_length_to_int(derobj->raw_length); i++) {
                derobj->raw_value.push_back(input.at(index++));
            }
        }

        // finish if nothing left to read
        if (index == input.size()) {
            finished = true;
        }
	}

	return root_node;
}

void delete_extensions() {
    // find out which child in TBSCertificate is extensions to override
    for (int i=0; i<root->get_object_by_name("TBSCertificate")->children.size(); i++) {
        if (root->get_object_by_name("TBSCertificate")->children[i]->name.compare("extensions") == 0) {
            root->get_object_by_name("TBSCertificate")->children.erase(root->get_object_by_name("TBSCertificate")->children.begin() + i);
            break;
        }
    }
}

void set_subject_alternative_names_extension() {
    // create structure for ASN.1 data
    shared_ptr<DERObject> derobj1, derobj2;
    vector<int> oid;
    string str;

    shared_ptr<DERObject> octet_str = shared_ptr<DERObject>(new DERObject);
    octet_str->raw_tag = ASN1_TYPE_OCTET_STRING;
    octet_str->pseudo_constructed = true;

    shared_ptr<DERObject> sequence = shared_ptr<DERObject>(new DERObject);
    sequence->raw_tag = ASN1_TYPE_SEQUENCE + 32;

    octet_str->children.push_back(sequence);


    //IA5String mit "localhost" und tag [2]

    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = 130;

    IA5StringManipulator m1 = IA5StringManipulator(derobj1);
    m1.set_value("localhost");

    sequence->children.push_back(derobj1);

    //IA5String mit "localhost." und tag [2]

    derobj1 = shared_ptr<DERObject>(new DERObject);
    derobj1->raw_tag = 130;

    m1 = IA5StringManipulator(derobj1);
    m1.set_value("localhost.");

    sequence->children.push_back(derobj1);



    // find out which child in TBSCertificate is extensions to override
    for (int i=0; i<root->get_object_by_name("TBSCertificate")->children.size(); i++) {
        if (root->get_object_by_name("TBSCertificate")->children[i]->name.compare("extensions") == 0) {
            cout << "test" << endl;
            for (int j=0; j < root->get_object_by_name("TBSCertificate")->children[i]->children[0]->children.size(); j++) {
                cout << "test2" << endl;
                if (root->get_object_by_name("TBSCertificate")->children[i]->children[0]->children[j]->children[0]->raw_value[0] == 85
                and root->get_object_by_name("TBSCertificate")->children[i]->children[0]->children[j]->children[0]->raw_value[1] == 29
                and root->get_object_by_name("TBSCertificate")->children[i]->children[0]->children[j]->children[0]->raw_value[2] == 17) {
                    root->get_object_by_name("TBSCertificate")->children[i]->children[0]->children[j]->children[1] = octet_str;
                }
            }
        }
    }
}

// sets the public key to the key specified in the KEY_PATH constant
// The file should contain the DER encoding of the SubjectPublicKeyInfo
// writes into the global variable SubjectPublicKeyInfo so that this method only has to be executed once
void get_public_key_from_file() {
    vector<byte> input = read_bytes(PUBKEY_PATH.c_str());
    SubjectPublicKeyInfo = parse_DER(input, true, false, true);
    SubjectPublicKeyInfo->name = "subjectPublicKeyInfo";
    SubjectPublicKeyInfo->children[0]->name = "subjectPublicKeyInfoAlgorithmSequence";
    SubjectPublicKeyInfo->children[0]->children[0]->name = "subjectPublicKeyInfoAlgorithm";
    if (SubjectPublicKeyInfo->children[0]->children.size() > 1) {
        SubjectPublicKeyInfo->children[0]->children[1]->name = "subjectPublicKeyInfoParameters";
    }
    SubjectPublicKeyInfo->children[1]->name = "subjectPublicKey";
}

void get_issuer() {
    vector<byte> input = read_bytes(CA_PATH.c_str());
    CA_issuer = parse_DER(input);

    // read subject of CA file to set as issuer in this file
    CA_issuer = CA_issuer->get_object_by_name("subject");
    CA_issuer->recalculate_lengths();
    CA_issuer->name = "issuer";
}

// sets the common name of the certificate (subject) to "localhost"
void set_common_name() {
    shared_ptr<Manipulator> m;

    for (shared_ptr<DERObject> derobj : root->get_object_by_name("subject")->children) {

        vector<int> common_name_oid = { 2, 5, 4, 3 };
        OIDManipulator *o = new OIDManipulator(derobj->children[0]->children[0]);


        if (o->get_value()[0] == common_name_oid[0] && o->get_value()[1] == common_name_oid[1] && o->get_value()[2] == common_name_oid[2] && o->get_value()[3] == common_name_oid[3]) {
            m = Manipulator::make_manipulator(derobj->children[0]->children[1]);
            switch (int(derobj->children[0]->children[1]->raw_tag)) {
                case ASN1_TYPE_PRINTABLESTRING: {
                    shared_ptr<PrintableStringManipulator> m2 = dynamic_pointer_cast<PrintableStringManipulator>(m);
                    m2->set_value(SET_COMMONNAME);
                    break;
                }

                case ASN1_TYPE_UTF8STRING: {
                    shared_ptr<UTF8StringManipulator> m3 = dynamic_pointer_cast<UTF8StringManipulator>(m);
                    m3->set_value(SET_COMMONNAME);
                    break;
                }

                default:
                    cout << "FAIL ! could not set common name ! (" << mapTags[int(derobj->raw_tag)] << ")" << endl;
                    exit(0);
            }

            delete o;
        }
    }
}


int main(int argc, char* argv[]) {
    string cert;

    if (argc == 7) {
        cert = CERT_PATH + argv[1];

        MAX_CERTS = atol(argv[2]);


        std::string do_sign(argv[3]);
        if (do_sign == "true") {
            SIGN_CERTS = true;
        }
        else if (do_sign == "false") {
            SIGN_CERTS = false;
        }
        else {
            std::cout << "Failed to recognize parameter 'sign'" << endl;
            exit(0);
        }


        std::string do_create_test_cert(argv[4]);
        if (do_create_test_cert == "true") {
            CREATE_TEST_CERT = true;
        }
        else if (do_create_test_cert == "false") {
            CREATE_TEST_CERT = false;
        }
        else {
            std::cout << "Failed to recognize parameter 'create_test_cert'" << endl;
            exit(0);
        }

        SET_COMMONNAME = argv[5];

        seed = atoi(argv[6]);

    }
    else {
        cout << "invalid parameters" << endl;
        exit(0);
    }




    // open log file
    LogFile.open("FuzzLog.txt", std::ofstream::out | std::ofstream::trunc);

    // read public key that should be used once
    get_public_key_from_file();

    // define CA_issuer
    //set_CA_issuer();
    get_issuer();

    LogFile << "\n\n Fuzzing Certificate: " << cert << "\n\n";

    /*cout << endl << endl << "Hexdump after reading certificate:" << endl;
    std::cout << std::hex ;
    for( byte b : read_bytes(cert.c_str()) ) printf("%02x ", b);
    std::cout << '\n' << std::dec;
    cout << endl << endl << endl;*/


    vector<byte> input = read_bytes(cert.c_str());

    root = parse_DER(input);
    //delete_extensions();

    // set the subject alt name correctly
    //set_subject_alternative_names_extension();
    //delete_extensions();

    /*cout << endl;
    vector<byte> result = root->raw_bytes();
    cout << endl << endl << "Hexdump after parsing certificate" << endl;
    for (byte b : result) {
        if (int(b) < 16)
            cout << "0";
        cout << hex << int(b) << " ";
    }
    cout << dec << endl << endl;*/

    cout << "Tree-like representation of parsed certificate:" << endl << endl;
    print_tree(root);

    // delete old content, if it already existed
    const char* exec = string("rm -R " + FUZZED_CERTS_FOLDER_NAME).c_str();
    system(exec);

    // create folder for fuzzed certificates
    if(mkdir(FUZZED_CERTS_FOLDER_NAME.c_str(), 0777) == -1) {
        cerr << endl << "Folder for fuzzed certs not created, because:  " << strerror(errno) << endl;
    }
    if(mkdir((FUZZED_CERTS_FOLDER_NAME + "/correctly_signed").c_str(), 0777) == -1) {
        cerr << endl << "Folder for correctly signed certs not created, because:  " << strerror(errno) << endl;
    }
    if(mkdir((FUZZED_CERTS_FOLDER_NAME + "/incorrectly_signed").c_str(), 0777) == -1) {
        cerr << endl << "Folder for incorrectly signed certs not created, because:  " << strerror(errno) << endl;
    }




    // set issuer, common name and public key correctly before fuzzing the certificate
    set_issuer(CA_issuer);
    set_SubjectPublicKeyInfo();
    set_common_name();

    // create certificate without extensions that is correctly signed
    if (CREATE_TEST_CERT) {
        cout << "creating test certificate ..." << endl;
        if(mkdir((FUZZED_CERTS_FOLDER_NAME + "/test").c_str(), 0777) == -1) {
            cerr << endl << "Folder for test certs not created, because:  " << strerror(errno) << endl;
        }
        delete_extensions();
        sign_certificate();
        root->recalculate_lengths();
        write_pem_file(root->raw_bytes(), true);
        write_der_file(root->raw_bytes(), true);
        CREATE_TEST_CERT = false;
        file_number = 0;


        // restore old values
        vector<byte> input = read_bytes(cert.c_str());
        root = parse_DER(input);
        set_issuer(CA_issuer);
        set_SubjectPublicKeyInfo();
        set_common_name();

        cout << "Test certificate created" << endl;
    }



    root->recalculate_lengths();

    // fuzz the certificate
    cout << "Fuzzing certificates ... " << endl;
    vector<shared_ptr<DERObject>> cert_field_vector = make_cert_field_vector(root);

    fuzz_engine_single_field(cert_field_vector);
    fuzz_engine_multiple_fields(cert_field_vector, 2, 50, 50);
    fuzz_engine_multiple_fields(cert_field_vector, 3, 500, 100);
    fuzz_engine_multiple_fields(cert_field_vector, 4, 500, 200);

    delete_extensions();
    // now do the fuzzing again without extensions (makes the certificates valid for some instances, plus adds more random cases)
    LogFile << "\n\nFuzzing without extensions\n\n";
    fuzz_engine_single_field(cert_field_vector);
    fuzz_engine_multiple_fields(cert_field_vector, 2, 500, 50);
    fuzz_engine_multiple_fields(cert_field_vector, 3, 500, 100);
    fuzz_engine_multiple_fields(cert_field_vector, 4, 500, 200);


    cout << endl << file_number << " certs created" << endl;


    /*cout << endl << "Hexdump of certificate with only signature, public key and issuer changed:" << endl;
    set_issuer_CA();
    set_SubjectPublicKeyInfo();
    sign_certificate();
    root->recalculate_lengths();
    result = root->raw_bytes();500
    for (byte b : result) {
        if (int(b) < 16)
            cout << "0";
        cout << hex << int(b) << " ";
    }
    cout << dec << endl << endl;


    cout << endl << "Hexdump of SubjectPublicKeyInfo" << endl;
    result = SubjectPublicKeyInfo->raw_bytes();
    for (byte b : result) {
        if (int(b) < 16)
            cout << "0";
        cout << hex << int(b) << " ";
    }
    cout << dec << endl << endl;

    cout << endl << "Hexdump of signature" << endl;
    result = root->get_object_by_name("signatureValue")->raw_bytes();
    for (byte b : result) {
        if (int(b) < 16)
            cout << "0";
        cout << hex << int(b) << " ";
    }
    cout << dec << endl << endl;

    print_tree(root);*/

    LogFile.close();

}



