#include <cassert>
#include <algorithm>
#include <array>
#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include "component_integrity.hpp"
#include "support.hpp"

extern "C" {
    #include "spdm_cma_req.h"
}

namespace phosphor::component_integrity
{
namespace
{
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using AssociationList =
    std::vector<std::tuple<std::string, std::string, std::string>>;
} // namespace

ComponentIntegrity::ComponentIntegrity(sdbusplus::bus::bus& bus, const char* path,
    bool componentIntegrityEnabled,
    spdm_conn_t *spdm_conn,
    sdbusplus::xyz::openbmc_project::Attestation::server::ComponentIntegrity::SecurityTechnologyType protocolType,
    std::string& protocolTypeVersion,
    std::string& updatedTime,
    sdbusplus::xyz::openbmc_project::Attestation::server::IdentityAuthentication::VerificationStatus status) :
    internal::ComponentIntegrityInterface(bus, path, action::defer_emit)
{
	this->enabled(componentIntegrityEnabled);
	this->type(protocolType);
	this->typeVersion(protocolTypeVersion);
	this->lastUpdated(updatedTime);
	this->responderVerificationStatus(status);
    this->spdm_conn = spdm_conn;

    log<level::INFO>("ComponentIntegrity Instance Created!");
}

ComponentIntegrity::~ComponentIntegrity()
{
    log<level::INFO>("ComponentIntegrity Instance Destroyed!");
}

uint8_t hex2byte(char c)
{
    if (c >= '0' && c <='9')
        return (uint8_t)(c - '0');
    else if (c >= 'a' && c <= 'f')
        return (uint8_t)(c - 'a') + 10;
    else if (c >= 'A' && c <= 'F')
        return (uint8_t)(c - 'A') + 10;
    else
        throw std::invalid_argument("Invalid hex string");
}

std::tuple<sdbusplus::message::object_path, std::string,
    std::string, std::string, std::string, std::string>
    ComponentIntegrity::spdmGetSignedMeasurements(
        std::vector<size_t> measurementIndices,
        std::string nonce,
        size_t slotId) 
{
    int i;
    libspdm_return_t status;
    sdbusplus::message::object_path certificate;
    std::string hashingAlg;
    std::string signedAlg;
    std::string version;
    std::string signedMeasurements;

    // Note, we donot set PUBKEY as it should be extracted from the certificate.
    std::string pubKey("PUBKEY");

    // set certificate path from associations
    bool found = false;
    //std::cout << "Associations:" << associations;
    auto assocs = this->associations();
    for (auto iter = assocs.begin();
            iter != assocs.end(); ++iter) {
        log<level::INFO>("[ComponentIntegrity] associations:");
        log<level::INFO>(std::get<0>(*iter).c_str());
        log<level::INFO>(std::get<1>(*iter).c_str());
        log<level::INFO>(std::get<2>(*iter).c_str());
        if (std::get<0>(*iter).compare("responder_identified_by") == 0) {
            certificate = std::string(std::get<2>(*iter));
            found = true;
            break;
        }
    }

    if (!found) {
            certificate = std::string("");
            throw std::runtime_error("[ComponentIntegrity] Device cert not found!");
    }

    // SPDM version
    if (this->spdm_conn->m_use_version == SPDM_MESSAGE_VERSION_11)
	    version = std::string("SPDM 1.1");
    else if (this->spdm_conn->m_use_version == SPDM_MESSAGE_VERSION_10)
	    version = std::string("SPDM 1.0");
    else if (this->spdm_conn->m_use_version == SPDM_MESSAGE_VERSION_12)
	    version = std::string("SPDM 1.2");
    else {
	    version = std::string("Version Unsupported!");
        std::cout << "SPDM Version :" << this->spdm_conn->m_use_version;
        throw std::runtime_error("[ComponentIntegrity] Unsupported SPDM Version!");
    }
    
    // Get Hashing Alg 
    switch (this->spdm_conn->m_use_measurement_hash_algo) {
        case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
            hashingAlg = std::string("TPM_ALG_SHA_512");
            break;
        case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
            hashingAlg = std::string("TPM_ALG_SHA_384");
            break;
        case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
            hashingAlg = std::string("TPM_ALG_SHA_256");
            break;
        default:
            throw std::runtime_error("[ComponentIntegrity] Unsupported HASH Algorithm!");
            hashingAlg = std::string("Unsupported HASH Algorithm!");
    }

    // Signed Algorithm
    switch(this->spdm_conn->m_use_asym_algo) {
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
            signedAlg = std::string("TPM_ALG_ECDSA_ECC_NIST_P384");
            break;
        case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
            signedAlg = std::string("TPM_ALG_ECDSA_ECC_NIST_P256");
            break;
        default:
            throw std::runtime_error("[ComponentIntegrity] Unsupported Signing Algorithm!");
            signedAlg = std::string("Unsupported Signing Algorithm!");
    }


    // convert c++ vector to c array
    size_t* indices = new size_t[measurementIndices.size()];
    for (i = 0; i < measurementIndices.size(); i++)
        indices[i] = measurementIndices[i];


    /* hexstring to byte array: two hex char map to 1 byte */
    assert(nonce.size() % 2 == 0 && nonce.size() > 0); // make sure hex string is convertable
    uint8_t *nonce_in = new uint8_t[nonce.size()/2];
    for (i = 0; i < nonce.size()/2; i+=2)
        nonce_in[i] = hex2byte(nonce[i*2]) << 4 | hex2byte(nonce[i*2 + 1]);
    
    // No need to return measurement blocks, all stored in L2 log.
    status = spdm_cma_get_signed_measurements(this->spdm_conn,
                slotId, nonce_in, indices, measurementIndices.size());
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        throw std::runtime_error("[ComponentIntegrity] get measurements failed!");
	    signedMeasurements = "";
    }

    uint8_t *l1l2 = (uint8_t *)libspdm_get_managed_buffer(&this->spdm_conn->l1l2);
    size_t l1l2_size = libspdm_get_managed_buffer_size(&this->spdm_conn->l1l2);

    std::string bin_l1l2;
    bin_l1l2.assign(l1l2, l1l2 + l1l2_size);
    signedMeasurements = base64_encode(bin_l1l2);

	auto response = make_tuple(certificate, hashingAlg, pubKey,
                               signedMeasurements, signedAlg, version);
    return response;
}

} // namespace component_integrity
