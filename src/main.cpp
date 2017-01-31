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
size_t MAX_CERTS = SIZE_MAX;

bool SIGN_CERTS = false;

bool CREATE_TEST_CERT = false;

string SET_COMMONNAME = "localhost";

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
    flips random bits in the DER-encoding and DOES NOT save the file after each bitflip.
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
        // LogFile << file_number << " flip bits\n";
        // write_pem_file(cert_content, false);
    }
}


/**
    fuzzes all fields in the vector cert_field_vector
*/
void fuzz_engine_single_field(vector<shared_ptr<DERObject>> cert_field_vector) {

    LogFile << "fuzzing single fields\n\n";
    stringstream LogFileStr;

    std::mt19937 rng(seed);
    std::uniform_int_distribution<size_t> dist(0, cert_field_vector.size() - 1);
    shared_ptr<DERObject> field = cert_field_vector.at(dist(rng));
    // for (shared_ptr<DERObject> field: cert_field_vector) {
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
        // for (shared_ptr<Manipulator> manipulator : manipulators) {
        dist = std::uniform_int_distribution<size_t>(0, manipulators.size() - 1);
        shared_ptr<Manipulator> manipulator = manipulators.at(dist(rng));
        dist = std::uniform_int_distribution<size_t>(0, manipulator->get_fixed_manipulations_count() + RANDOM_MANIPULATIONS_COUNT);
        int i = dist(rng);
            // for (int i=0; i < (manipulator->get_fixed_manipulations_count() + RANDOM_MANIPULATIONS_COUNT); i++) {
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
            // }

            // restore state that our tree had before applying manipulations of 'manipulator'
            manipulator->restore_initial_values();
            root->recalculate_lengths();
        // }
    // }
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

const vector<byte> kBaseKey = {
    0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81,
    0x89, 0x02, 0x81, 0x81, 0x00, 0xf7, 0x55, 0x77, 0xdb, 0x15, 0xbe, 0x26,
    0x44, 0x41, 0xf0, 0xc1, 0x8c, 0x3b, 0xe9, 0x0b, 0xb9, 0x2e, 0xf9, 0x6d,
    0x69, 0x5d, 0x64, 0x8a, 0xd5, 0x52, 0xc1, 0x8b, 0xf6, 0x49, 0x9b, 0x6f,
    0xef, 0xd7, 0xe9, 0x50, 0x22, 0xec, 0xa2, 0x3f, 0xf2, 0x96, 0x98, 0xc4,
    0xe8, 0x11, 0x58, 0x0f, 0x96, 0x51, 0x16, 0xf5, 0x71, 0xd7, 0x83, 0x1a,
    0x38, 0x68, 0x49, 0x0c, 0x7c, 0xb4, 0x0b, 0x54, 0x88, 0xbe, 0x40, 0x46,
    0x70, 0xc7, 0x7e, 0xd9, 0x7d, 0xed, 0x9a, 0x56, 0x3a, 0x5c, 0xa9, 0xab,
    0xb9, 0xa5, 0xb3, 0xf4, 0x21, 0xbd, 0xae, 0x30, 0x6e, 0x8b, 0x07, 0xab,
    0x5d, 0xca, 0x8b, 0x24, 0xc0, 0x7c, 0xac, 0x83, 0x3c, 0xa1, 0x5d, 0xc7,
    0x05, 0xbb, 0x1b, 0xe2, 0xc0, 0xd1, 0xa0, 0xbd, 0xca, 0x09, 0x75, 0x90,
    0x92, 0x81, 0x75, 0x13, 0x71, 0xc2, 0xf7, 0x03, 0x09, 0x5b, 0x96, 0xaf,
    0xd1, 0x02, 0x03, 0x01, 0x00, 0x01};

// sets the public key to the key specified in the KEY_PATH constant
// The file should contain the DER encoding of the SubjectPublicKeyInfo
// writes into the global variable SubjectPublicKeyInfo so that this method only has to be executed once
void get_public_key_from_file() {
    // TODO: allow using a different key
    // vector<byte> input = read_bytes(PUBKEY_PATH.c_str());
    SubjectPublicKeyInfo = parse_DER(kBaseKey, true, false, true);
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

const vector<byte> kBaseCert = {
    0x30, 0x82, 0x07, 0x79, 0x30, 0x82, 0x06, 0x61, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x10, 0x0b, 0xfd, 0xb4, 0x09, 0x0a, 0xd7, 0xb5, 0xe6, 0x40,
    0xc3, 0x0b, 0x16, 0xc9, 0x52, 0x9a, 0x27, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x75,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
    0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c,
    0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63,
    0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10, 0x77,
    0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e,
    0x63, 0x6f, 0x6d, 0x31, 0x34, 0x30, 0x32, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x2b, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x53,
    0x48, 0x41, 0x32, 0x20, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64,
    0x20, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
    0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17,
    0x0d, 0x31, 0x36, 0x30, 0x33, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x5a, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x35, 0x31, 0x37, 0x31, 0x32,
    0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x81, 0xfd, 0x31, 0x1d, 0x30, 0x1b,
    0x06, 0x03, 0x55, 0x04, 0x0f, 0x0c, 0x14, 0x50, 0x72, 0x69, 0x76, 0x61,
    0x74, 0x65, 0x20, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0b, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03, 0x13, 0x02, 0x55, 0x53,
    0x31, 0x19, 0x30, 0x17, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
    0x37, 0x3c, 0x02, 0x01, 0x02, 0x13, 0x08, 0x44, 0x65, 0x6c, 0x61, 0x77,
    0x61, 0x72, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x05,
    0x13, 0x07, 0x35, 0x31, 0x35, 0x37, 0x35, 0x35, 0x30, 0x31, 0x24, 0x30,
    0x22, 0x06, 0x03, 0x55, 0x04, 0x09, 0x13, 0x1b, 0x38, 0x38, 0x20, 0x43,
    0x6f, 0x6c, 0x69, 0x6e, 0x20, 0x50, 0x20, 0x4b, 0x65, 0x6c, 0x6c, 0x79,
    0x2c, 0x20, 0x4a, 0x72, 0x20, 0x53, 0x74, 0x72, 0x65, 0x65, 0x74, 0x31,
    0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x11, 0x13, 0x05, 0x39, 0x34,
    0x31, 0x30, 0x37, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69,
    0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0d,
    0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63,
    0x6f, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c,
    0x47, 0x69, 0x74, 0x48, 0x75, 0x62, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e,
    0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x67,
    0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82, 0x01,
    0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01,
    0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe7, 0x88, 0x5c, 0xf2, 0x96, 0x5c,
    0x97, 0x18, 0x1c, 0xba, 0x98, 0xe2, 0x03, 0xf1, 0x7f, 0x39, 0x91, 0x91,
    0xc2, 0x6f, 0xd9, 0x96, 0xe7, 0x28, 0x40, 0x64, 0xcd, 0x4c, 0xa9, 0x81,
    0x12, 0x03, 0x6c, 0xae, 0x7f, 0xe6, 0xc6, 0x19, 0xe0, 0x5a, 0x63, 0xf0,
    0x6c, 0x0b, 0xd4, 0x68, 0xb3, 0xff, 0xfd, 0x3e, 0xfd, 0x25, 0xcf, 0xb5,
    0x59, 0x73, 0x29, 0xc4, 0xc8, 0xb3, 0xf4, 0xf2, 0xba, 0xc9, 0x94, 0x51,
    0x16, 0xe2, 0x28, 0xd1, 0xdd, 0x9b, 0xc7, 0x8d, 0xb7, 0x34, 0x0e, 0xa1,
    0x38, 0xbd, 0x91, 0x4e, 0xd6, 0xe7, 0x7e, 0xcf, 0xb2, 0xd0, 0xf1, 0x52,
    0xfd, 0x84, 0xe9, 0x41, 0x27, 0xa5, 0x4e, 0xea, 0xbe, 0x16, 0xec, 0x2d,
    0xb3, 0x9b, 0xfa, 0x68, 0x0c, 0x1e, 0x37, 0x23, 0x1c, 0x60, 0x3d, 0x07,
    0x07, 0x26, 0xe4, 0x91, 0xda, 0x2c, 0x16, 0x80, 0xdc, 0x70, 0x13, 0x73,
    0x27, 0xdd, 0x80, 0x73, 0xc2, 0x39, 0x11, 0x50, 0xd4, 0x73, 0x73, 0xab,
    0xff, 0x88, 0xd2, 0xc9, 0x9c, 0x33, 0xc6, 0xef, 0x64, 0x76, 0x60, 0x65,
    0x07, 0x37, 0x87, 0x32, 0xfb, 0x2a, 0x74, 0x7f, 0x12, 0x5f, 0xd9, 0x8d,
    0x6a, 0x15, 0xed, 0x5f, 0x14, 0x69, 0xc1, 0x99, 0xc1, 0x89, 0x48, 0xf0,
    0xdf, 0xa3, 0xe0, 0x37, 0xeb, 0x3d, 0x18, 0xb5, 0x86, 0xad, 0xa7, 0xdd,
    0xd3, 0x64, 0xf4, 0xbb, 0x1f, 0x58, 0xcd, 0xde, 0x5e, 0xce, 0x43, 0x31,
    0xba, 0x4a, 0x84, 0x01, 0x0e, 0xc0, 0x28, 0x82, 0x22, 0x8e, 0xf6, 0x96,
    0x3c, 0x02, 0x5b, 0x2b, 0xfe, 0x76, 0x5c, 0xb8, 0x48, 0xcb, 0x6b, 0xe9,
    0x18, 0xdc, 0xa5, 0xca, 0x78, 0xbf, 0x0d, 0x00, 0xf5, 0xf1, 0xb0, 0x4f,
    0x4f, 0xe6, 0x46, 0xd6, 0xeb, 0xf4, 0x41, 0x03, 0xfd, 0x2e, 0xe6, 0x3f,
    0x8e, 0x83, 0xbe, 0x14, 0xa0, 0xce, 0x4e, 0x57, 0xab, 0xe3, 0x02, 0x03,
    0x01, 0x00, 0x01, 0xa3, 0x82, 0x03, 0x7a, 0x30, 0x82, 0x03, 0x76, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    0x3d, 0xd3, 0x50, 0xa5, 0xd6, 0xa0, 0xad, 0xee, 0xf3, 0x4a, 0x60, 0x0a,
    0x65, 0xd3, 0x21, 0xd4, 0xf8, 0xf8, 0xd6, 0x0f, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x88, 0x5c, 0x48, 0x67, 0x19,
    0xcc, 0xa0, 0x76, 0x59, 0x2d, 0x11, 0x79, 0xc3, 0xbe, 0xa2, 0xac, 0x87,
    0x22, 0x27, 0x5b, 0x30, 0x25, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x1e,
    0x30, 0x1c, 0x82, 0x0a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
    0x6f, 0x6d, 0x82, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x69, 0x74, 0x68,
    0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
    0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x75, 0x06, 0x03, 0x55, 0x1d, 0x1f,
    0x04, 0x6e, 0x30, 0x6c, 0x30, 0x34, 0xa0, 0x32, 0xa0, 0x30, 0x86, 0x2e,
    0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x33, 0x2e,
    0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d,
    0x2f, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x65, 0x76, 0x2d, 0x73, 0x65, 0x72,
    0x76, 0x65, 0x72, 0x2d, 0x67, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x34,
    0xa0, 0x32, 0xa0, 0x30, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
    0x2f, 0x63, 0x72, 0x6c, 0x34, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65,
    0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x68, 0x61, 0x32, 0x2d,
    0x65, 0x76, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2d, 0x67, 0x31,
    0x2e, 0x63, 0x72, 0x6c, 0x30, 0x4b, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
    0x44, 0x30, 0x42, 0x30, 0x37, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86,
    0xfd, 0x6c, 0x02, 0x01, 0x30, 0x2a, 0x30, 0x28, 0x06, 0x08, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1c, 0x68, 0x74, 0x74, 0x70,
    0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69,
    0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x50, 0x53,
    0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01, 0x30, 0x81, 0x88,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x7c,
    0x30, 0x7a, 0x30, 0x24, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f,
    0x63, 0x73, 0x70, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74,
    0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x52, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x30, 0x02, 0x86, 0x46, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
    0x2f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2e, 0x64, 0x69, 0x67,
    0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x44, 0x69,
    0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x53, 0x48, 0x41, 0x32, 0x45, 0x78,
    0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x41,
    0x2e, 0x63, 0x72, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x82, 0x01, 0x7f, 0x06, 0x0a,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02, 0x04, 0x82,
    0x01, 0x6f, 0x04, 0x82, 0x01, 0x6b, 0x01, 0x69, 0x00, 0x76, 0x00, 0xa4,
    0xb9, 0x09, 0x90, 0xb4, 0x18, 0x58, 0x14, 0x87, 0xbb, 0x13, 0xa2, 0xcc,
    0x67, 0x70, 0x0a, 0x3c, 0x35, 0x98, 0x04, 0xf9, 0x1b, 0xdf, 0xb8, 0xe3,
    0x77, 0xcd, 0x0e, 0xc8, 0x0d, 0xdc, 0x10, 0x00, 0x00, 0x01, 0x53, 0x61,
    0x89, 0xea, 0x1e, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02,
    0x21, 0x00, 0x87, 0x1d, 0x21, 0x18, 0xfd, 0x13, 0x8a, 0xdb, 0xfb, 0x0e,
    0x96, 0x36, 0xca, 0x68, 0xd1, 0x1c, 0x29, 0x6c, 0xfa, 0x07, 0x11, 0xc9,
    0x34, 0xf3, 0xad, 0x8d, 0x2c, 0xae, 0x56, 0x74, 0xa7, 0xe1, 0x02, 0x20,
    0x27, 0xa4, 0x6a, 0xbd, 0x86, 0xd2, 0x5f, 0x5b, 0xca, 0x2d, 0xe5, 0xfb,
    0xbe, 0x99, 0xce, 0x7c, 0x20, 0x1f, 0x4b, 0x66, 0x3c, 0x94, 0x1e, 0x51,
    0x34, 0xcc, 0x24, 0xea, 0xeb, 0x36, 0x42, 0x20, 0x00, 0x76, 0x00, 0x68,
    0xf6, 0x98, 0xf8, 0x1f, 0x64, 0x82, 0xbe, 0x3a, 0x8c, 0xee, 0xb9, 0x28,
    0x1d, 0x4c, 0xfc, 0x71, 0x51, 0x5d, 0x67, 0x93, 0xd4, 0x44, 0xd1, 0x0a,
    0x67, 0xac, 0xbb, 0x4f, 0x4f, 0xfb, 0xc4, 0x00, 0x00, 0x01, 0x53, 0x61,
    0x89, 0xe9, 0xe7, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02,
    0x21, 0x00, 0xd9, 0xa5, 0xde, 0x52, 0xfb, 0x7b, 0x68, 0xf2, 0x4e, 0xe5,
    0x70, 0x37, 0x96, 0x06, 0x18, 0x89, 0x01, 0x28, 0x98, 0x4e, 0x4d, 0xab,
    0x34, 0x04, 0xf6, 0xea, 0x55, 0x5a, 0x33, 0x7c, 0x61, 0x5b, 0x02, 0x20,
    0x35, 0x4a, 0xab, 0x90, 0x83, 0x83, 0x66, 0x94, 0x60, 0xfa, 0x48, 0x61,
    0xa7, 0xc6, 0xa0, 0xeb, 0x90, 0x7c, 0x9a, 0xed, 0x29, 0xe0, 0x95, 0x00,
    0x9a, 0x44, 0x43, 0x6e, 0x26, 0x27, 0x46, 0xf6, 0x00, 0x77, 0x00, 0x56,
    0x14, 0x06, 0x9a, 0x2f, 0xd7, 0xc2, 0xec, 0xd3, 0xf5, 0xe1, 0xbd, 0x44,
    0xb2, 0x3e, 0xc7, 0x46, 0x76, 0xb9, 0xbc, 0x99, 0x11, 0x5c, 0xc0, 0xef,
    0x94, 0x98, 0x55, 0xd6, 0x89, 0xd0, 0xdd, 0x00, 0x00, 0x01, 0x53, 0x61,
    0x89, 0xea, 0x99, 0x00, 0x00, 0x04, 0x03, 0x00, 0x48, 0x30, 0x46, 0x02,
    0x21, 0x00, 0xe7, 0x9b, 0x75, 0x92, 0xb6, 0x5b, 0xc4, 0xf7, 0xd1, 0x82,
    0x8b, 0x34, 0xb1, 0xf9, 0x41, 0xad, 0x1a, 0x64, 0x24, 0xd9, 0x64, 0xe8,
    0x92, 0x83, 0xe0, 0xa3, 0x58, 0x5f, 0x8a, 0xff, 0x33, 0x20, 0x02, 0x21,
    0x00, 0xfa, 0xd8, 0x79, 0x7a, 0xc1, 0x82, 0xc7, 0x80, 0xf6, 0x35, 0x16,
    0x5a, 0x80, 0x78, 0x22, 0xf9, 0x9c, 0x66, 0xdb, 0x21, 0x8d, 0x7b, 0x28,
    0x9d, 0x3f, 0x0c, 0x20, 0x6d, 0x6e, 0xd7, 0x31, 0x7c, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x01, 0x00, 0x8b, 0x6c, 0xdb, 0x64, 0xc6, 0xeb, 0x29,
    0xab, 0x27, 0x2a, 0xf2, 0x1d, 0x44, 0xa5, 0xb9, 0x80, 0x5f, 0x4c, 0x0c,
    0xe4, 0x3a, 0x16, 0xee, 0x13, 0x3f, 0x15, 0x57, 0x73, 0xe0, 0xb2, 0x77,
    0x2a, 0x67, 0xed, 0xca, 0x4d, 0x72, 0x77, 0xc8, 0xff, 0x3d, 0x2c, 0x51,
    0xac, 0x04, 0x0d, 0xd8, 0xca, 0xff, 0x7e, 0xb2, 0x9e, 0x2b, 0xc3, 0x44,
    0xd5, 0xc3, 0x23, 0x8b, 0x7d, 0xa6, 0x25, 0xb0, 0x6a, 0xa5, 0x6b, 0x4a,
    0xff, 0xec, 0x02, 0xf9, 0xab, 0xcf, 0xa6, 0x50, 0x54, 0x6c, 0xda, 0x73,
    0x3f, 0x9d, 0xdc, 0xb9, 0x33, 0x05, 0xfd, 0x0b, 0x2c, 0xc4, 0x8b, 0x4f,
    0x18, 0xd3, 0xf9, 0xfc, 0xe4, 0xfd, 0x02, 0x3d, 0x41, 0xc4, 0x0f, 0xcd,
    0xa1, 0xf5, 0x99, 0x2a, 0x1e, 0x2e, 0x7d, 0x5e, 0xdc, 0xcf, 0x7a, 0x58,
    0x44, 0x34, 0xb8, 0x04, 0x5f, 0x84, 0x10, 0x54, 0x38, 0x97, 0x91, 0x98,
    0xfb, 0x2a, 0x78, 0x58, 0x90, 0x3f, 0xc5, 0x2b, 0xd8, 0xb1, 0x31, 0xd6,
    0x79, 0x6c, 0x51, 0x0f, 0x5f, 0xe7, 0x97, 0xad, 0xbf, 0x45, 0xdf, 0x45,
    0x37, 0x63, 0x64, 0x69, 0xc4, 0x55, 0xa3, 0x30, 0xb1, 0x45, 0x59, 0x5e,
    0x16, 0xb0, 0x47, 0x4c, 0x5c, 0x6a, 0x20, 0xfe, 0xa4, 0x0e, 0x7c, 0x62,
    0x2c, 0x49, 0x41, 0xad, 0x99, 0xe0, 0xb5, 0x8d, 0x3b, 0x89, 0xeb, 0x5a,
    0x61, 0x95, 0x4b, 0x40, 0xdf, 0xc4, 0x4f, 0x2a, 0x8b, 0x41, 0xfb, 0x6c,
    0x7f, 0xc4, 0xde, 0x73, 0x04, 0xe4, 0x95, 0xb8, 0xef, 0x9b, 0xc3, 0x53,
    0x26, 0xa6, 0xda, 0x21, 0x58, 0x9f, 0x63, 0x0a, 0xb0, 0x34, 0xdf, 0xb8,
    0x95, 0x1c, 0x52, 0xdc, 0x5e, 0x65, 0x36, 0x50, 0x3f, 0x8a, 0x5d, 0x76,
    0x20, 0xe8, 0x1b, 0x46, 0x2a, 0x0b, 0x23, 0xad, 0xa8, 0xf0, 0x6d, 0x03,
    0x68, 0x45, 0x10, 0x80, 0x73, 0x5f, 0xf2, 0xf4, 0x86};

int getCert(unsigned int seed_in) {
  seed = seed_in;
  // TODO: allow passing in a cert/cert file name
  bool readCert = false;
  string cert;

  // read public key that should be used once
  get_public_key_from_file();

  // TODO: why?
  // set_CA_issuer();
  get_issuer();

  // reading cert
  if (!readCert) {
    vector<byte> input = read_bytes(cert.c_str());
    root = parse_DER(input);
  } else {
    // use hard coded cert instead of input
    root = parse_DER(kBaseCert);
  }

  // TODO: why would we want to do that?
  // delete_extensions();

  // set issuer, common name and public key correctly before fuzzing the
  // certificate
  // TODO: fuzz this as well
  set_issuer(CA_issuer);
  set_SubjectPublicKeyInfo();
  set_common_name();

  root->recalculate_lengths();

  // fuzz the certificate
  vector<shared_ptr<DERObject>> cert_field_vector =
      make_cert_field_vector(root);

  std::mt19937 rng(seed);
  std::bernoulli_distribution bdist;
  if (bdist(rng)) {
    fuzz_engine_single_field(cert_field_vector);
  } else {
    fuzz_engine_multiple_fields(cert_field_vector, 4, 1, 500);
  }
}

int main(int argc, char *argv[]) {
  string cert;
  bool lib = false;

  if (argc == 7) {
    cert = CERT_PATH + argv[1];

    MAX_CERTS = atol(argv[2]);

    std::string do_sign(argv[3]);
    if (do_sign == "true") {
      SIGN_CERTS = true;
    } else if (do_sign == "false") {
      SIGN_CERTS = false;
    } else {
      std::cout << "Failed to recognize parameter 'sign'" << endl;
      exit(0);
    }

    std::string do_create_test_cert(argv[4]);
    if (do_create_test_cert == "true") {
      CREATE_TEST_CERT = true;
    } else if (do_create_test_cert == "false") {
      CREATE_TEST_CERT = false;
    } else {
      std::cout << "Failed to recognize parameter 'create_test_cert'" << endl;
      exit(0);
    }

    SET_COMMONNAME = argv[5];

    seed = atoi(argv[6]);

  } else if (argc >= 2 && string(argv[1]) == "lib") {
    // In this case this is a library call and we have different parameters.
    // ./CertFuzzer lib seed
    lib = true;
    seed = atoi(argv[2]);
    // TODO: randomize SET_COMMONNAME based on seed
  } else {
    cout << "invalid parameters" << endl;
    exit(0);
  }

  // open log file
  LogFile.open("FuzzLog.txt", std::ofstream::out | std::ofstream::trunc);

  // read public key that should be used once
  get_public_key_from_file();

  // define CA_issuer
  // set_CA_issuer();
  get_issuer();


  // std::cout << endl << endl << "Hexdump after reading certificate:" << endl;
  // std::cout << std::hex;
  // for (byte b : read_bytes(cert.c_str()))
  //   printf("0x%02x, ", b);
  // std::cout << '\n' << std::dec;
  // cout << endl << endl << endl;

  // reading cert
  if (!lib) {
    LogFile << "\n\n Fuzzing Certificate: " << cert << "\n\n";
    vector<byte> input = read_bytes(cert.c_str());
    root = parse_DER(input);
  } else {
    // use hard coded cert instead of input
    root = parse_DER(kBaseCert);
  }

  // delete_extensions();

  // set the subject alt name correctly
  // set_subject_alternative_names_extension();
  // delete_extensions();

  /*cout << endl;
  vector<byte> result = root->raw_bytes();
  cout << endl << endl << "Hexdump after parsing certificate" << endl;
  for (byte b : result) {
      if (int(b) < 16)
          cout << "0";
      cout << hex << int(b) << " ";
  }
  cout << dec << endl << endl;*/

  // cout << "Tree-like representation of parsed certificate:" << endl << endl;
  // print_tree(root);

  // delete old content, if it already existed
  // if (!lib) {
    const char *exec = string("rm -R " + FUZZED_CERTS_FOLDER_NAME).c_str();
    system(exec);

    // create folder for fuzzed certificates
    if (mkdir(FUZZED_CERTS_FOLDER_NAME.c_str(), 0777) == -1) {
      cerr << endl
           << "Folder for fuzzed certs not created, because:  "
           << strerror(errno) << endl;
    }
    if (mkdir((FUZZED_CERTS_FOLDER_NAME + "/correctly_signed").c_str(), 0777) ==
        -1) {
      cerr << endl
           << "Folder for correctly signed certs not created, because:  "
           << strerror(errno) << endl;
    }
    if (mkdir((FUZZED_CERTS_FOLDER_NAME + "/incorrectly_signed").c_str(),
              0777) == -1) {
      cerr << endl
           << "Folder for incorrectly signed certs not created, because:  "
           << strerror(errno) << endl;
    }
  // }

  // set issuer, common name and public key correctly before fuzzing the
  // certificate
  set_issuer(CA_issuer);
  set_SubjectPublicKeyInfo();
  set_common_name();

  // create certificate without extensions that is correctly signed
  if (CREATE_TEST_CERT) {
    cout << "creating test certificate ..." << endl;
    if (mkdir((FUZZED_CERTS_FOLDER_NAME + "/test").c_str(), 0777) == -1) {
      cerr << endl
           << "Folder for test certs not created, because:  " << strerror(errno)
           << endl;
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
  vector<shared_ptr<DERObject>> cert_field_vector =
      make_cert_field_vector(root);

  std::mt19937 rng(seed);
  std::bernoulli_distribution bdist;
  if (bdist(rng)) {
    fuzz_engine_single_field(cert_field_vector);
  } else {
    fuzz_engine_multiple_fields(cert_field_vector, 4, 1, 500);
  }
  // fuzz_engine_multiple_fields(cert_field_vector, 3, 500, 100);
  // fuzz_engine_multiple_fields(cert_field_vector, 4, 500, 200);

  // delete_extensions();
  // // now do the fuzzing again without extensions (makes the certificates valid
  // // for some instances, plus adds more random cases)
  // LogFile << "\n\nFuzzing without extensions\n\n";
  // fuzz_engine_single_field(cert_field_vector);
  // fuzz_engine_multiple_fields(cert_field_vector, 2, 500, 50);
  // fuzz_engine_multiple_fields(cert_field_vector, 3, 500, 100);
  // fuzz_engine_multiple_fields(cert_field_vector, 4, 500, 200);

  cout << endl << file_number << " certs created" << endl;

  /*cout << endl << "Hexdump of certificate with only signature, public key and
  issuer changed:" << endl;
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



