#pragma once

#include <functional>
#include <memory>
#include <bit>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Chassis/TrustedComponent/server.hpp>

namespace internal
{
using TrustedComponentInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Chassis::server::TrustedComponent>;
} // namespace internal

namespace phosphor::trusted_component
{

/** @class TrustedComponent
 *  @brief OpenBMC TrustedComponent entry implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.TrustedComponent DBus API
 */
class TrustedComponent : public internal::TrustedComponentInterface
{
  public:
    TrustedComponent() = delete;
    TrustedComponent(const TrustedComponent&) = delete;
    TrustedComponent& operator=(const TrustedComponent&) = delete;
    TrustedComponent(TrustedComponent&&) = delete;
    TrustedComponent& operator=(TrustedComponent&&) = delete;
    virtual ~TrustedComponent();

    /** @brief Constructor for the TrustedComponent Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] certificates - Object path to certificates 
     *  @param[in] firmwareVersion - Trusted component firmware version
     */
    TrustedComponent(sdbusplus::bus::bus& bus, const char* path,
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
								std::string& uuid);

};

} // namespace phosphor::trusted_component
