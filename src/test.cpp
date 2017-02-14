
#include <stdint.h>
#include <vector>
#include <cstdio>
#include <cstdlib>

#include "CertificateMutator.h"

// Test main.cpp getCert function for libFuzzer mutator.

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("I require a seed as first argument.\n");
        return 1;
    }
    printf("%s", getCert(atoi(argv[1]), kBaseCert).c_str());

    return 0;
}
