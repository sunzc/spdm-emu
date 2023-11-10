#ifndef _SUPPORT_H_
#define _SUPPORT_H_
std::string der_to_pem(const std::vector<unsigned char>& der_bytes);
std::string der_chain_to_pem(const std::vector<unsigned char>& der_bytes);
std::string base64_encode(const std::string& input);
#endif
