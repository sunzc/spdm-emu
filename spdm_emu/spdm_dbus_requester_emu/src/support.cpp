#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "support.hpp"
extern "C" {
    #include "internal/libspdm_crypt_lib.h"
}

using namespace std;

static const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string base64_encode(const string& input) {
    string output;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(b64_alphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        output.push_back(b64_alphabet[(val << 8) >> (valb + 8) & 0x3F]);
    }
    while (output.size() % 4) {
        output.push_back('=');
    }
    return output;
}

/*
extern bool libspdm_x509_get_cert_from_cert_chain(const uint8_t *cert_chain,
                                                  size_t cert_chain_length,
                                                  const int32_t cert_index, const uint8_t **cert,
                                                  size_t *cert_length);
*/
string der_chain_to_pem(const vector<unsigned char>& der_bytes) {
    const uint8_t *certp;
    bool ret;
    size_t chain_len;
    size_t cert_len;
    int32_t index;
    size_t cur_len;

    chain_len = der_bytes.size();
    index = 0;
    cur_len = 0;
    string pem_string = ""; 
    while (cur_len < chain_len) { 
        ret = libspdm_x509_get_cert_from_cert_chain(der_bytes.data(),
                                                  chain_len,
                                                  index, &certp,
                                                  &cert_len);
        if (!ret) {
            cout << "Error in convert der cert chain to pem chain!" << endl; 
            return "";
        }

        // append one cert
        pem_string += "-----BEGIN CERTIFICATE-----\n";
        pem_string += base64_encode(string(certp, certp + cert_len)) + "\n";
        pem_string += "-----END CERTIFICATE-----\n";

        // debug 
        // cout <<"certp:" << certp <<endl;
        // cout <<"cert_len:" << cert_len <<endl;
        // cout <<"cur_len:" << cur_len <<endl;
        // cout <<"chain_len:" << chain_len <<endl;
        // cout <<"index:" << index <<endl;

        cur_len += cert_len;
        index += 1;
    }
    return pem_string;
}

string der_to_pem(const vector<unsigned char>& der_bytes) {
    string pem_string = "-----BEGIN CERTIFICATE-----\n";
    pem_string += base64_encode(string(der_bytes.begin(), der_bytes.end())) + "\n";
    pem_string += "-----END CERTIFICATE-----\n";
    return pem_string;
}
