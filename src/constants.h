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

#ifndef DERDEVIL_CONSTANTS_H
#define DERDEVIL_CONSTANTS_H


const int ASN1_TYPE_EOF = 0;
const int ASN1_TYPE_BOOLEAN = 1;
const int ASN1_TYPE_INTEGER = 2;
const int ASN1_TYPE_BIT_STRING = 3;
const int ASN1_TYPE_OCTET_STRING = 4;
const int ASN1_TYPE_NULL = 5;
const int ASN1_TYPE_OBJECT_IDENTIFIER = 6;
const int ASN1_TYPE_OBJECT_DESCRIPTOR = 7;
const int ASN1_TYPE_EXTERNAL = 8;
const int ASN1_TYPE_REAL = 9;
const int ASN1_TYPE_ENUMERATED = 10;
const int ASN1_TYPE_EMBEDDED_PDV = 11;
const int ASN1_TYPE_UTF8STRING = 12;
const int ASN1_TYPE_RELATIVE_OID = 13;
const int ASN1_TYPE_RESERVED1 = 14;
const int ASN1_TYPE_RESERVED2 = 15;
const int ASN1_TYPE_SEQUENCE = 16;
const int ASN1_TYPE_SET = 17;
const int ASN1_TYPE_NUMERICSTRING = 18;
const int ASN1_TYPE_PRINTABLESTRING = 19;
const int ASN1_TYPE_T61STRING = 20;
const int ASN1_TYPE_VIDEOTEXSTRING = 21;
const int ASN1_TYPE_IA5STRING = 22;
const int ASN1_TYPE_UTCTime = 23;
const int ASN1_TYPE_GeneralizedTime = 24;
const int ASN1_TYPE_GraphicString = 25;
const int ASN1_TYPE_VisibleString = 26;
const int ASN1_TYPE_GeneralString = 27;
const int ASN1_TYPE_UniversalString = 28;
const int ASN1_TYPE_CHARACTER_STRING = 29;
const int ASN1_TYPE_BMPString = 30;


const string mapTags[32] = {"EOF", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING", "NULL", "OBJECT IDENTIFIER", "Object Descriptor", "EXTERNAL", "REAL (float)", "ENUMERATED", "EMBEDDED PDV",
                    "UTF8String", "RELATIVE-OID", "(reserved)", "(reserved)", "SEQUENCE", "SET", "NumericString", "PrintableString", "T61String", "VideotexString", "IA5String", "UTCTime",
                     "GeneralizedTime", "GraphicString", "VisibleString", "GeneralString", "UniversalString", "CHARACTER STRING", "BMPString"};

const string FUZZED_CERTS_FOLDER_NAME = "../fuzzed_certs";  ///< Name of the folder where fuzzed certificates will be stored
const string FUZZED_CERTS_PREFIX = "cert_";     ///< Prefix for fuzzed certs. Increasing index including file extension will be appended

const size_t RANDOM_STRING_MANIPULATIONS = 3;


const string PUBKEY_PATH = "../Misc/keys/leaf-cert-pubkey.der";    ///< Path to public key
const string CA_PATH = "../Misc/certificates/ca/ca-root.der";   ///< Path to CA file
const string CERT_PATH = "../Misc/certificates/leaf/";        ///< Path to certificate that will be fuzzed
const string CA_KEY_PATH = "../Misc/keys/ca-key.pkcs8";         ///< path to CA private key for signing (has to be pkcs8)


#endif
