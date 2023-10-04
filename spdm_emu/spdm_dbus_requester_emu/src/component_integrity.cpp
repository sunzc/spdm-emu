#include "component_integrity.hpp"

#include <algorithm>
#include <array>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

extern "C" {
    #include "spdm_requester_emu.h"
    #include "dbus_get_certificate.h"
}

namespace phosphor::component_integrity
{
namespace
{
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
} // namespace

ComponentIntegrity::ComponentIntegrity(sdbusplus::bus::bus& bus, const char* path,
    bool componentIntegrityEnabled,
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
    sdbusplus::message::object_path
        certificate("/xyz/openbmc_project/certs/systems/system01/gf_cert1");
	std::string hashingAlg("SHA256");
	std::string pubKey("PUBKEY");
	std::string signedMeasurements("SIGNEDMEAUREMENTS");
	std::string signedAlg("SIGNINGALG");
	std::string version("VERSION_1.0");
    int i;
    libspdm_return_t status;

    // convert c++ vector to c array
    size_t* indices = new size_t[measurementIndices.size()];
    for (i = 0; i < measurementIndices.size(); i++)
        indices[i] = measurementIndices[i];


    /* hexstring to byte array: two hex char map to 1 byte */
    assert(nonce.size() % 2 == 0 && nonce.size() > 0); // make sure hex string is convertable
    uint8_t *nonce_in = new size_t[nonce.size()/2];
    for (i = 0; i < nonce.size()/2; i+=2)
        nonce_in[i] = hex2byte(nonce[i*2]) << 4 | hex2byte(nonce[i*2 + 1]);
    
    // No need to return measurement blocks, all stored in L2 log.
    status = dbus_get_signed_measurements(slot_id, nonce_in, indices,
            measurementIndices.size());
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        // TODO throw error msg or set measurements empty
	    signedMeasurements("");
    }

	auto response = make_tuple(certificate, hashingAlg, pubKey,
                               signedMeasurements, signedAlg, version);
    return response;
}

} // namespace component_integrity
