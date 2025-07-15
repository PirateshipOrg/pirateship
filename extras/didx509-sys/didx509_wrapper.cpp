#include "wrapper.h"
#include "didx509cpp/didx509cpp.h"
#include <cstring>
#include <memory>

extern "C" {

int didx509_resolve(
    const char* chain_pem,
    const char* did,
    int ignore_time,
    char** result,
    int* result_length
) {
    try {
        std::string chain_str(chain_pem);
        std::string did_str(did);
        bool ignore_time_bool = (ignore_time != 0);
        
        std::string doc = didx509::resolve(chain_str, did_str, ignore_time_bool);
        
        // Allocate memory for the result
        *result_length = doc.length();
        *result = static_cast<char*>(malloc(*result_length + 1));
        if (*result == nullptr) {
            return DIDX509_ERROR;
        }
        
        // Copy the result
        std::memcpy(*result, doc.c_str(), *result_length);
        (*result)[*result_length] = '\0';
        
        return DIDX509_SUCCESS;
    } catch (std::runtime_error& e) {
        *result = nullptr;
        *result_length = 0;
        return DIDX509_ERROR;
    }
}

int didx509_resolve_jwk(
    const char** chain_pem_array,
    int chain_length,
    const char* did,
    int ignore_time,
    char** result,
    int* result_length
) {
    try {
        std::vector<std::string> chain_vec;
        for (int i = 0; i < chain_length; i++) {
            chain_vec.emplace_back(chain_pem_array[i]);
        }
        
        std::string did_str(did);
        bool ignore_time_bool = (ignore_time != 0);
        
        std::string jwk = didx509::resolve_jwk(chain_vec, did_str, ignore_time_bool);
        
        // Allocate memory for the result
        *result_length = jwk.length();
        *result = static_cast<char*>(malloc(*result_length + 1));
        if (*result == nullptr) {
            return DIDX509_ERROR;
        }
        
        // Copy the result
        std::memcpy(*result, jwk.c_str(), *result_length);
        (*result)[*result_length] = '\0';
        
        return DIDX509_SUCCESS;
    } catch (...) {
        *result = nullptr;
        *result_length = 0;
        return DIDX509_ERROR;
    }
}

void didx509_free_result(char* result) {
    if (result != nullptr) {
        free(result);
    }
}

}
