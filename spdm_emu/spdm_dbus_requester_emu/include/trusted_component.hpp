#pragma once

#include <functional>
#include <memory>
#include <bit>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Inventory/Item/TrustedComponent/server.hpp>
#include <xyz/openbmc_project/Inventory/Decorator/Asset/server.hpp>
#include <xyz/openbmc_project/Common/UUID/server.hpp>
#include <xyz/openbmc_project/Association/Definitions/server.hpp>

namespace internal
{
    // TODO: FRU interface also has property named Version, which conflicts
    // with Software/Version interface's property Version. Will use Version
    // for firmwareVersion. How to specify which interface's property here? 
using TrustedComponentInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Association::server::Definitions,
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent,
    sdbusplus::xyz::openbmc_project::Inventory::Decorator::server::Asset,
    sdbusplus::xyz::openbmc_project::Common::server::UUID>;
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
        std::string& certificatesLocation,
        std::string& firmwareVersion,
        std::string& manufacturer,
        std::string& serialNumber,
        std::string& sku,
        sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent::ComponentAttachType type,
        std::string& uuid);

};

} // namespace phosphor::trusted_component
