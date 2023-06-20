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
using ::sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
} // namespace


TrustedComponent::TrustedComponent(sdbusplus::bus::bus& bus,
                const char* path,
								sdbusplus::message::object_path& certificates,
								std::string& firmwareVersion,
								sdbusplus::message::object_path& activeSoftwareImage,
								std::vector<sdbusplus::message::object_path>& componentIntegrity,
								std::vector<sdbusplus::message::object_path>& componentsProtected,
								sdbusplus::message::object_path& integratedInto,
								std::vector<sdbusplus::message::object_path>& softwareImages,
								std::string& manufacturer,
								std::string& serialNumber,
								std::string& sku,
								sdbusplus::xyz::openbmc_project::Chassis::server::TrustedComponent::ComponentAttachType type,
								std::string& uuid) :
    internal::TrustedComponentInterface(bus, path, action::defer_emit)
{
		this->firmwareVersion(firmwareVersion);
		this->certificates(certificates);
		this->activeSoftwareImage(activeSoftwareImage);
		this->componentIntegrity(componentIntegrity);
		this->componentsProtected(componentsProtected);
		this->integratedInto(integratedInto);
		this->softwareImages(softwareImages);
		this->manufacturer(manufacturer);
		this->serialNumber(serialNumber);
        this->sku(sku);
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
