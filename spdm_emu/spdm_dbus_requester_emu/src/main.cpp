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

int main(int argc, char* argv[]) {

  /* TODO: Fake object path */
	auto ciObjPath = std::string("/xyz/openbmc_project/ComponentIntegrity/ci01");
	auto tcObjPath = std::string("/xyz/openbmc_project/Chassis/chassis01/TrustedComponent/tc01");
	auto GFCertObjPath = std::string("/xyz/openbmc_project/certs/systems/system01/cert1");
	auto certsObjPath = std::string("/xyz/openbmc_project/certs/systems/system01");
	auto pcObjPath = std::string("/xyz/openbmc_project/Systems/system01");
	auto certFile = std::string("/tmp/GFcert01.pem");

  /* TODO: TrustedComponent example */
	auto lastUpdated = std::string("04/18/2023");
	auto typeVersion = std::string("1.0");
	auto firmwareVersion = std::string("ExampleFirmware_1.0");
	auto manufacturer = std::string("Google LLC");
	auto sku = std::string("SKU_Example");
	auto uuid = std::string("UUID_Example");
	auto SN = std::string("SerialNumber_Example");
	
  /* TODO: Example path refered by example object */
	sdbusplus::message::object_path componentPath(tcObjPath);
	sdbusplus::message::object_path certificatesPath(certsObjPath);
	sdbusplus::message::object_path
	        activeSoftwareImage("/xyz/openbmc_project/software/software01");
	sdbusplus::message::object_path componentIntegrityPath(ciObjPath);
	std::vector<sdbusplus::message::object_path>
	        componentIntegrityList = {componentIntegrityPath};
	sdbusplus::message::object_path protectedComponentPath(pcObjPath);
	std::vector<sdbusplus::message::object_path>
	        protectedComponentsList = {protectedComponentPath};
	sdbusplus::message::object_path integratedInto(pcObjPath);
	sdbusplus::message::object_path requester("/xyz/openbmc_project/Systems/bmc0");
	sdbusplus::message::object_path
	        requesterAuthentication("/xyz/openbmc_project/certs/systems/system01/bmc0_cert1");
	sdbusplus::message::object_path
	        responderAuthentication("/xyz/openbmc_project/certs/systems/devices/cert1");

  /* TODO: Example type info (using GF as example) */
	auto type =
	        sdbusplus::xyz::openbmc_project::server::ComponentIntegrity::SecurityTechnologyType::SPDM;
	auto attachType =
					sdbusplus::xyz::openbmc_project::Chassis::server::TrustedComponent::ComponentAttachType::Integrated;
	auto verificationStatus = 
	        sdbusplus::xyz::openbmc_project::ComponentIntegrity::SPDM::server::IdentityAuthentication::VerificationStatus::Success;


  static boost::asio::io_context ioc;
  static auto conn =
        std::make_shared<sdbusplus::asio::connection>(ioc);

  std::string s = "spdm_requester_emu";
  char* char_array = new char[40];
  strcpy(char_array, s.c_str());
  printf("%s version 0.1\n", "spdm_dbus_requester_emu");
  srand((unsigned int)time(NULL));
  process_args(char_array, argc, argv);

  //test_c_func(1, 2); 

  /* TODO: Request example service name */
  conn->request_name("xyz.openbmc_project.SPDM");
  sdbusplus::asio::object_server server =
      sdbusplus::asio::object_server(conn);
  sdbusplus::bus_t& bus = static_cast<sdbusplus::bus_t&>(*conn);

  // Add sdbusplus ObjectManager
  sdbusplus::server::manager::manager ciObjManager(bus, ciObjPath.c_str());
  sdbusplus::server::manager::manager tcObjManager(bus, tcObjPath.c_str());
  sdbusplus::server::manager::manager certObjManager(bus, GFCertObjPath.c_str());

  phosphor::component_integrity::ComponentIntegrity componentIntegrity(
	    bus, ciObjPath.c_str(), true, type, typeVersion,
			lastUpdated, componentPath, protectedComponentsList,
			requester, requesterAuthentication, responderAuthentication,
			verificationStatus);

  phosphor::trusted_component::TrustedComponent trustedComponent(
	    bus, tcObjPath.c_str(), certificatesPath, firmwareVersion,
			activeSoftwareImage, componentIntegrityList, protectedComponentsList,
			integratedInto, protectedComponentsList,
			manufacturer, SN, sku,
			attachType, uuid);

	// TODO do GetCertificates and populate certs objects.
  phosphor::certificate::Certificate cert(bus, GFCertObjPath.c_str(), certFile);

  log<level::ERR>("new HelloWorld D-Bus Agent started!");

	ioc.run();

  log<level::ERR>("HelloWorld D-Bus Agent exited!");

  return 0;
}
