Installation
---

Run ./build.sh or manually compile Botan in Libraries/ and then compile the Certificate Fuzzer using
cmake .
make

Note: cmake is needed to build the project



Usage
---

To run the fuzzer, call ./runCertFuzzer.sh

You can pass the following arguments:

base_cert="cert_name.der" to define which certificate will be fuzzed. This argument must be present. The certificates must be stored in Certificate_Fuzzer/Misc/certificates/server/ and must be DER-encoded. If it is PEM encoded, you can transform it to DER, for example with the following command:
openssl x509 -in cert.pem -inform PEM -outform DER -out cert.der

sign=true or sign=false to either store correctly signed versions of mutated certificates or not. Default is true (store correctly signed versions).

create_test=true or create_test=false to either create or not create a test certificate in fuzzed_certs/test. Default is false. See section "Test Certificate" below for more information.

max_certs=<number> to set the maximum amount of created certificates. Default is 0 (no maximum). 

set_common_name="common name" to set the common name field. Default is "localhost"

Example call:
./runCertFuzzer.sh base_cert=github.der sign=true max_certs=500000 create_test=false set_common_name="localhost"

This will store the mutated certificates in fuzzed_certs/correctly_signed/ for the correctly signed certificates and in fuzzed_certs/incorrectly_signed for the incorrectly signed certificates. 



Test Certificate
---

To verify that the program correctly signs a certificate you can create a test certificate with the create_test=true flag. This creates a variation of your base_certificate where the issuer and the public key as well as the signature are correctly set but no changes that "break" the certificate. If it was verifiable before it should still be verifiable afterwards. Because the Certificate Fuzzer Tool does not yet consider X.509 extensions there might be semantical inconsistencies with the rest of the certificate that prevent the altered certificate to be verifiable after setting issuer, public key and signature. This is why the extensions are completely removed for the test certificate, too. You should be able to use this certificate in a TLS connection where the server is provided with the correct private key and the client is provided with the corresponding CA. The test certificate will be stored in fuzzed_certs/test/
To simply verify the certificate you could, for example, run

openssl verify -CAfile Misc/certificates/ca/ca-root.pem fuzzed_certs/test/cert_test.pem




Setting up your own CA
---

You can use your own CA file. To do so either replace Misc/certificates/ca/ca-root.pem and Misc/keys/ca-key.pkcs8 or change the CA_PATH and CA_KEY_PATH in src/config.h.



Setting up your own leaf certificate key
---

If you want to use another private key than the Misc/keys/leaf-cert-privkey.pem you will also have to create a new public key file aswell (leaf-cert-pubkey.der). This is because the public key is needed for the certificate. You can either replace these files or change the CERT_PATH and PUBKEY_PATH in src/config.h. The following OpenSSL command can be helpful for this task:
	openssl rsa -in leaf-cert-privkey.pem -out leaf-cert-pubkey.der -outform DER -pubout
this will create the public key from the private key.



Some details on the process flow
---

Before a certificate is fuzzed, first the issuer, common name and subjectPublicKeyInfo will be set correctly, such that the certificate can be verified with the given CA and can be used in a TLS connection with the given server private key. After setting these fields, the certificate will be fuzzed, where said fields can be altered to be incorrect again. If you choose the option to sign certificates correctly, there will also be stored altered versions of the certificate where a new signature is calculated. The correctly signed versions will only be generated for syntax preserving manipulations on the certificate. Arbitrary manipulations can corrupt the file and it is not always meaningful to calculate and set a signature in the general case.




Notes
---

* At the time this tool is working on Linux systems only. Tested on Ubuntu 14.04 LTS
