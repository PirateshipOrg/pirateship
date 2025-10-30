#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Return codes for the C wrapper functions
#define DIDX509_SUCCESS 0
#define DIDX509_ERROR -1

// C wrapper for the resolve function
int didx509_resolve(
    const char* chain_pem,
    const char* did,
    int ignore_time,
    char** result,
    int* result_length
);

// C wrapper for the resolve_jwk function  
int didx509_resolve_jwk(
    const char** chain_pem_array,
    int chain_length,
    const char* did,
    int ignore_time,
    char** result,
    int* result_length
);

// Function to free memory allocated by the wrapper
void didx509_free_result(char* result);

#ifdef __cplusplus
}
#endif
