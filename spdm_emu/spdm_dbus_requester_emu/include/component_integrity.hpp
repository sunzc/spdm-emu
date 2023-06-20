#pragma once

#include <functional>
#include <memory>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Certs/Certificate/server.hpp>
#include <xyz/openbmc_project/ComponentIntegrity/server.hpp>
#include <xyz/openbmc_project/ComponentIntegrity/SPDM/server.hpp>
#include <xyz/openbmc_project/ComponentIntegrity/SPDM/IdentityAuthentication/server.hpp>
#include <xyz/openbmc_project/ComponentIntegrity/SPDM/MeasurementSet/server.hpp>
#include <xyz/openbmc_project/Inventory/Item/Rot/server.hpp>

namespace internal
{
using ComponentIntegrityInterface = sdbusplus::server::object_t<
		sdbusplus::xyz::openbmc_project::Inventory::Item::server::Rot,
		sdbusplus::xyz::openbmc_project::server::ComponentIntegrity,
    sdbusplus::xyz::openbmc_project::ComponentIntegrity::server::SPDM,
    sdbusplus::xyz::openbmc_project::ComponentIntegrity::SPDM::server::IdentityAuthentication,
    sdbusplus::xyz::openbmc_project::ComponentIntegrity::SPDM::server::MeasurementSet>;
} // namespace internal

namespace phosphor::component_integrity
{

/** @class ComponentIntegrity
 *  @brief OpenBMC ComponentIntegrity entry implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.ComponentIntegrity DBus API
 *  xyz.openbmc_project.ComponentIntegrity.SPDM DBus API
 *  xyz.openbmc_project.ComponentIntegrity.SPDM.IdentityAuthentication DBus API
 *  xyz.openbmc_project.ComponentIntegrity.SPDM.MeasurementSet DBus API
 */
class ComponentIntegrity : public internal::ComponentIntegrityInterface
{
  public:
    ComponentIntegrity() = delete;
    ComponentIntegrity(const ComponentIntegrity&) = delete;
    ComponentIntegrity& operator=(const ComponentIntegrity&) = delete;
    ComponentIntegrity(ComponentIntegrity&&) = delete;
    ComponentIntegrity& operator=(ComponentIntegrity&&) = delete;
    virtual ~ComponentIntegrity();

    /** @brief Constructor for the ComponentIntegrity Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] enabled - Whether ComponentIntegrity is enabled
     *  @param[in] type - The security protocol type
     *  @param[in] typeVersion - The version of the security protocol
     *  @param[in] lastUpdated - The time of the last update
     *  @param[in] targetComponentURI - The object path of the target trusted
		 *             component.
     *  @param[in] componentsProtected - List of components that is protected
		 *             by the target trusted component.
     */
    ComponentIntegrity(sdbusplus::bus::bus& bus,  const char* path,
                bool enabled,
								sdbusplus::xyz::openbmc_project::server::ComponentIntegrity::SecurityTechnologyType type,
								std::string& typeVersion, std::string& lastUpdated,
								sdbusplus::message::object_path& targetComponentURI,
							  std::vector<sdbusplus::message::object_path> componentsProtected,
								sdbusplus::message::object_path& requester,
								sdbusplus::message::object_path& requesterAuthentication,
								sdbusplus::message::object_path& responderAuthentication,
	              sdbusplus::xyz::openbmc_project::ComponentIntegrity::SPDM::server::IdentityAuthentication::VerificationStatus status);

    /** @brief Implementation for SPDMGetSignedMeasurements
     *  This method generates an SPDM cryptographic signed statement
		 *  over the given nonce and measurements of the SPDM Responder.
     *
     *  @param[in] measurementIndices - An array of indices that identify
		 *             the measurement blocks to sign.
     *  @param[in] nonce - A 32-byte hex-encoded string that is signed
		 *             with the measurements. The value should be unique.
     *  @param[in] slotId - The slot identifier for the certificate containing
		 *             the private key to generate the signature over the measurements.
     *
     *  @return measurementResponse[std::tuple<sdbusplus::message::object_path,
		 *          std::string, std::string, std::string, std::string, std::string>]
		 *          - The response will contain a struct with following fields:
		 *          Certificate, HashingAlgorithm, PublicKey, SignedMeasurements,
		 *          SignedAlgorithm, Version. Among them, Certificate refers to
		 *          certificate object corresponding to the SPDM slot identifier
		 *          that can be used to validate the signature.
     */
    std::tuple<sdbusplus::message::object_path, std::string,
		    std::string, std::string, std::string, std::string>
        spdmGetSignedMeasurements(
            std::vector<uint32_t> measurementIndices,
            std::string nonce,
            uint32_t slotId) override;

};

} // namespace phosphor::component_integrity
