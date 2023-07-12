#include <phosphor-logging/log.hpp>
#include <iostream>
#include <cstring>

#include "component_integrity.hpp"
#include "trusted_component.hpp"
#include "certificate.hpp"

#include <systemd/sd-event.h>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <boost/stacktrace.hpp>
#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/property.hpp>
#include <string>
#include <vector>

extern "C" {
    #include "spdm_requester_emu.h"
    #include "test_c_header.h"
}

using namespace phosphor::logging;
using AssociationList =
    std::vector<std::tuple<std::string, std::string, std::string>>;

/* TODO: Emulate a Software class. In real world, fw version should be managed by
 * other daemon. */
class Software
{
  public:
    Software(boost::asio::io_context& ioc, sdbusplus::asio::connection& bus,
                sdbusplus::asio::object_server& objServer, std::string objPath, std::string intfName, std::string ver) :
        ioc_(ioc),
        bus_(bus), objServer_(objServer)
    {
		swversion_ = ver;
        swintf_ = objServer_.add_unique_interface(
            objPath, intfName,
            [this](sdbusplus::asio::dbus_interface& demo) {
            demo.register_property_r<std::string>(
                "Version", sdbusplus::vtable::property_::const_,
                [this](const auto&) { return swversion_; });
            });
    }

  private:
    boost::asio::io_context& ioc_;
    sdbusplus::asio::connection& bus_;
    sdbusplus::asio::object_server& objServer_;

    std::unique_ptr<sdbusplus::asio::dbus_interface> swintf_;
    std::string swversion_= "1.2";

};

/* TODO: Emulate a System class. In real world, system should be managed by
 * other daemons. */
class System
{
  public:
    System(boost::asio::io_context& ioc, sdbusplus::asio::connection& bus,
                sdbusplus::asio::object_server& objServer, std::string objPath, std::string intfName) :
        ioc_(ioc),
        bus_(bus), objServer_(objServer)
    {
        systemintf_ = objServer_.add_unique_interface(
            objPath, intfName,
            [this](sdbusplus::asio::dbus_interface& demo) {
            demo.register_property_r<std::string>(
                "Name", sdbusplus::vtable::property_::const_,
                [this](const auto&) { return "system name"; });
            });
    }

  private:
    boost::asio::io_context& ioc_;
    sdbusplus::asio::connection& bus_;
    sdbusplus::asio::object_server& objServer_;

    std::unique_ptr<sdbusplus::asio::dbus_interface> systemintf_;

};

int main(int argc, char* argv[]) {

  /* TODO: Fake object path */
	auto ciObjPath = std::string("/xyz/openbmc_project/ComponentIntegrity/ci01");
	auto tcObjPath = std::string("/xyz/openbmc_project/Chassis/chassis01/TrustedComponent/tc01");
	auto GFCertObjPath = std::string("/xyz/openbmc_project/certs/systems/system01/cert1");
	auto certsLocation= std::string("system01");
	auto pcObjPath = std::string("/xyz/openbmc_project/Systems/system01");
	auto certFile = std::string("/tmp/GFcert01.pem");
	auto activeSwObjPath = std::string("/xyz/openbmc_project/software/software01");
	auto oldSwObjPath = std::string("/xyz/openbmc_project/software/software02");

  /* TODO: TrustedComponent example */
	auto lastUpdated = std::string("04/18/2023");
	auto typeVersion = std::string("1.0");
	auto firmwareVersion = std::string("ExampleFirmware_1.0");
	auto manufacturer = std::string("Google LLC");
	auto sku = std::string("SKU_Example");
	auto uuid = std::string("UUID_Example");
	auto SN = std::string("SerialNumber_Example");
	
  /* TODO: Example path refered by example object */
	//sdbusplus::message::object_path componentPath(tcObjPath);
	//sdbusplus::message::object_path
	//        activeSoftwareImage("/xyz/openbmc_project/software/software01");
	//sdbusplus::message::object_path componentIntegrityPath(ciObjPath);
	//std::vector<sdbusplus::message::object_path>
	//        componentIntegrityList = {componentIntegrityPath};
	//sdbusplus::message::object_path protectedComponentPath(pcObjPath);
	//std::vector<sdbusplus::message::object_path>
	//        protectedComponentsList = {protectedComponentPath};
	//sdbusplus::message::object_path integratedInto(pcObjPath);
	//sdbusplus::message::object_path
	//        requesterAuthentication("/xyz/openbmc_project/certs/systems/system01/bmc0_cert1");
	//sdbusplus::message::object_path
	//        responderAuthentication("/xyz/openbmc_project/certs/systems/devices/cert1");

  /* TODO: Example type info (using GF as example) */
	auto type = sdbusplus::xyz::openbmc_project::Inventory::Decorator::server::ComponentIntegrity::SecurityTechnologyType::SPDM;
	auto attachType = sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent::ComponentAttachType::Integrated;
	auto verificationStatus = sdbusplus::xyz::openbmc_project::Inventory::Decorator::server::IdentityAuthentication::VerificationStatus::Success;

  /* Associations */
  AssociationList componentIntegrityAssocs{};

  static boost::asio::io_context ioc;
  static auto conn = std::make_shared<sdbusplus::asio::connection>(ioc);

  std::string s = "spdm_requester_emu";
  char* char_array = new char[40];
  strcpy(char_array, s.c_str());
  printf("%s version 0.1\n", "spdm_dbus_requester_emu");
  srand((unsigned int)time(NULL));
  process_args(char_array, argc, argv);

  /* TODO: Request example service name */
  conn->request_name("xyz.openbmc_project.SPDM");
  sdbusplus::asio::object_server server =
      sdbusplus::asio::object_server(conn);
  sdbusplus::bus_t& bus = static_cast<sdbusplus::bus_t&>(*conn);

  // test generic properties
  Software app(ioc, *conn, server, activeSwObjPath, "xyz.openbmc_project.Software.Version", "1.2");
  Software app2(ioc, *conn, server, oldSwObjPath, "xyz.openbmc_project.Software.Version", "1.2");

  // test protected systems
  System sysObj(ioc, *conn, server, pcObjPath, "xyz.openbmc_project.Inventory.Item.System");

  // Add sdbusplus ObjectManager
  sdbusplus::server::manager::manager ciObjManager(bus, ciObjPath.c_str());
  sdbusplus::server::manager::manager tcObjManager(bus, tcObjPath.c_str());
  sdbusplus::server::manager::manager certObjManager(bus, GFCertObjPath.c_str());

  // TODO: Create more dbus objects for certs, system, software images,

  phosphor::component_integrity::ComponentIntegrity componentIntegrity(
	    bus, ciObjPath.c_str(), true, type, typeVersion, lastUpdated, verificationStatus);

  phosphor::trusted_component::TrustedComponent trustedComponent(
	    bus, tcObjPath.c_str(), certsLocation, firmwareVersion, manufacturer, SN, sku, attachType, uuid);

	// TODO do GetCertificates and populate certs objects.
  phosphor::certificate::Certificate cert(bus, GFCertObjPath.c_str(), certFile);


  // Add associations for ComponentIntegrity object
  auto ciAssocs = AssociationList{
        {"reporting", "reported_by", tcObjPath},
        {"protecting", "protected_by", pcObjPath},
        {"requester_identitified_by","identifying", GFCertObjPath},
        {"responder_identitified_by","identifying", GFCertObjPath}
        };
  componentIntegrity.associations(ciAssocs);

  auto tcAssocs = AssociationList{
        {"reported_by", "reporting", ciObjPath},
        {"protecting", "protected_by", pcObjPath},
        {"integrated_into","contains", pcObjPath},
        {"actively_running","actively_runs_on", activeSwObjPath},
        {"runs","runs_on", oldSwObjPath}
        };
  trustedComponent.associations(tcAssocs);

  log<level::ERR>("new HelloWorld D-Bus Agent started!");

	ioc.run();

  log<level::ERR>("HelloWorld D-Bus Agent exited!");

  return 0;
}
