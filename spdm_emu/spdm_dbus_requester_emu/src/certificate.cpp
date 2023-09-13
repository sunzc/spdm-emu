#include "certificate.hpp"

#include <algorithm>
#include <array>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <fstream>

namespace phosphor::certificate
{
namespace
{
using ::phosphor::logging::level;
using ::phosphor::logging::log;
} // namespace

Certificate::Certificate(sdbusplus::bus::bus& bus, const char* path,
    std::string &filePath) :
    internal::CertificateInterface(bus, path)
{
    std::string pem_cert, cert_str;
    std::ifstream cert_file(filePath.c_str());
    cert_file >> cert_str;

    // TODO Parse cert from file, support only PEM chain.
    log<level::INFO>(filePath.c_str());
    log<level::INFO>("Certificate Instance Created!");

    // TODO Hardcode for testing
    certificateString(cert_str);
    subject("test subject");
    issuer("test issuer");
    keyUsage({"test keyusage1","test keyusage2"});
    validNotAfter(24*60*60*1000);
    validNotBefore(24*60*60*900);
}

void Certificate::replace(const std::string filePath)
{
    // TODO we may need to replace it when cert updated.
    log<level::INFO>("replace existing certificate!");
}

Certificate::~Certificate()
{
    log<level::INFO>("Certificate Instance Destroyed!");
}

} // namespace phosphor::certificate
