#pragma once

#include <functional>
#include <memory>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Certs/Certificate/server.hpp>
#include <xyz/openbmc_project/Certs/Replace/server.hpp>

namespace internal
{
using CertificateInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate,
    sdbusplus::xyz::openbmc_project::Certs::server::Replace>;
} // namespace internal

namespace phosphor::certificate
{

/** @class Certificate
 */
class Certificate : public internal::CertificateInterface
{
  public:
    Certificate() = delete;
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
    Certificate(Certificate&&) = delete;
    Certificate& operator=(Certificate&&) = delete;
    virtual ~Certificate();

    /** @brief Constructor for the Certificate Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Object path to attach to.
     *  @param[in] filePath - Certificate file path. 
     */
    Certificate(sdbusplus::bus::bus& bus, const char* path,
		            std::string& filePath);

    /** @brief Validate certificate and replace the existing certificate
     *  @param[in] filePath - Certificate file path.
     */
    void replace(const std::string filePath) override;
};

} // namespace phosphor::certificate
