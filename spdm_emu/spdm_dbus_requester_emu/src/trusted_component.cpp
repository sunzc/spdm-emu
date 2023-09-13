#include "trusted_component.hpp"

#include <algorithm>
#include <array>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>

namespace phosphor::trusted_component
{
namespace
{
using ::phosphor::logging::level;
using ::phosphor::logging::log;
//using ::sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
} // namespace


TrustedComponent::TrustedComponent(sdbusplus::bus::bus& bus,
    const char* path,
    std::string& certificatesLocation,
    std::string& firmwareVersion,
    std::string& manufacturer,
    std::string& serialNumber,
    std::string& sku,
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent::ComponentAttachType type,
    std::string& uuid) :
        internal::TrustedComponentInterface(bus, path, action::defer_emit)
{
    //this->version(firmwareVersion);
    this->certificatesLocation(certificatesLocation);
    this->manufacturer(manufacturer);
    this->serialNumber(serialNumber);
    //this->sku(sku);
    this->trustedComponentType(type);
    this->uuid(uuid);
    
    log<level::INFO>("TrustedComponent Instance Created!");
    
    return;
}

TrustedComponent::~TrustedComponent()
{
    log<level::INFO>("TrustedComponent Instance Destroyed!");
}

} // namespace trusted_component
