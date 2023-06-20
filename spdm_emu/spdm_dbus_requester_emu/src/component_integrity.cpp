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
    uint8_t m_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    extern SOCKET m_socket;
    extern void *m_spdm_context;
    extern void *m_scratch_buffer;
    uint8_t m_other_slot_id = 0;
    void *spdm_client_init(void);
    libspdm_return_t pci_doe_init_requester(void);
    SOCKET CreateSocketAndHandShake(SOCKET *sock, uint16_t port_number);
    bool communicate_platform_data(SOCKET socket, uint32_t command,
                                   const uint8_t *send_buffer, size_t bytes_to_send,
                                   uint32_t *response,
                                   size_t *bytes_to_receive,
                                   uint8_t *receive_buffer);
    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    libspdm_return_t do_measurement_via_spdm(const uint32_t *session_id);
    #endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
    
    #if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)
    libspdm_return_t do_authentication_via_spdm(void);
    #endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/
    
    libspdm_return_t do_session_via_spdm(bool use_psk);
    libspdm_return_t do_certificate_provising_via_spdm(uint32_t* session_id);
    
    bool platform_client_routine(uint16_t port_number)
    {
        SOCKET platform_socket;
        bool result;
        uint32_t response;
        size_t response_size;
        libspdm_return_t status;
    
        if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
            m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE) {
            m_socket = CreateSocketAndHandShake(&platform_socket, port_number);
            if (m_socket == INVALID_SOCKET) {
                printf("Create platform service socket fail\n");
    #ifdef _MSC_VER
                WSACleanup();
    #endif
                return false;
            }
    
            printf("Continuing with SPDM flow...\n");
        }
        else {
            result = init_client(&platform_socket, port_number);
            if (!result) {
    #ifdef _MSC_VER
                WSACleanup();
    #endif
                return false;
            }
    
            m_socket = platform_socket;
        }
    
        if (m_use_transport_layer != SOCKET_TRANSPORT_TYPE_NONE) {
            response_size = sizeof(m_receive_buffer);
            result = communicate_platform_data(
                m_socket,
                SOCKET_SPDM_COMMAND_TEST,
                (uint8_t *)"Client Hello!",
                sizeof("Client Hello!"), &response,
                &response_size, m_receive_buffer);
            if (!result) {
                goto done;
            }
        }
    
        if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
            status = pci_doe_init_requester ();
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                printf("pci_doe_init_requester - %x\n", (uint32_t)status);
                goto done;
            }
        }
    
        m_spdm_context = spdm_client_init();
        if (m_spdm_context == NULL) {
            goto done;
        }
    
        /* Do test - begin*/
    #if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)
        status = do_authentication_via_spdm();
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("do_authentication_via_spdm - %x\n", (uint32_t)status);
            goto done;
        }
    #endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/
    
    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
        if ((m_exe_connection & EXE_CONNECTION_MEAS) != 0) {
            status = do_measurement_via_spdm(NULL);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                printf("do_measurement_via_spdm - %x\n",
                       (uint32_t)status);
                goto done;
            }
        }
    #endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
        /* when use --trans NONE, skip secure session  */
        if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
            if (m_use_version >= SPDM_MESSAGE_VERSION_12) {
                status = do_certificate_provising_via_spdm(NULL);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    printf("do_certificate_provising_via_spdm - %x\n",
                           (uint32_t)status);
                    goto done;
                }
            }
        }
        else
        {
    #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)
            if (m_use_version >= SPDM_MESSAGE_VERSION_11) {
                if ((m_exe_session & EXE_SESSION_KEY_EX) != 0) {
                    status = do_session_via_spdm(false);
                    if (LIBSPDM_STATUS_IS_ERROR(status)) {
                        printf("do_session_via_spdm - %x\n",
                               (uint32_t)status);
                        goto done;
                    }
                }
    
                if ((m_exe_session & EXE_SESSION_PSK) != 0) {
                    status = do_session_via_spdm(true);
                    if (LIBSPDM_STATUS_IS_ERROR(status)) {
                        printf("do_session_via_spdm - %x\n",
                               (uint32_t)status);
                        goto done;
                    }
                }
                if ((m_exe_session & EXE_SESSION_KEY_EX) != 0) {
                    if (m_other_slot_id != 0) {
                        m_use_slot_id = m_other_slot_id;
                        status = do_session_via_spdm(false);
                        if (LIBSPDM_STATUS_IS_ERROR(status)) {
                            printf("do_session_via_spdm - %x\n",
                                   (uint32_t)status);
                            goto done;
                        }
                    }
                }
            }
    #endif /*(LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)*/
        }
        /* Do test - end*/
    
    done:
        response_size = 0;
        result = communicate_platform_data(
            m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - m_exe_mode,
            NULL, 0, &response, &response_size, NULL);
    
        if (m_spdm_context != NULL) {
            libspdm_deinit_context(m_spdm_context);
            free(m_spdm_context);
            free(m_scratch_buffer);
        }
    
        closesocket(platform_socket);
        if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
            m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE) {
            closesocket(m_socket);
        }
    
    #ifdef _MSC_VER
        WSACleanup();
    #endif
    
        return true;
    }
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
								sdbusplus::xyz::openbmc_project::server::ComponentIntegrity::SecurityTechnologyType
								protocolType,
								std::string& protocolTypeVersion, std::string& updatedTime,
								sdbusplus::message::object_path& targetURI,
								std::vector<sdbusplus::message::object_path> protectedComponents,
								sdbusplus::message::object_path& requester,
								sdbusplus::message::object_path& requesterAuthentication,
								sdbusplus::message::object_path& responderAuthentication,
	              sdbusplus::xyz::openbmc_project::ComponentIntegrity::SPDM::server::IdentityAuthentication::VerificationStatus status) :
    internal::ComponentIntegrityInterface(bus, path, action::defer_emit)
{
		this->enabled(componentIntegrityEnabled);
		this->type(protocolType);
		this->typeVersion(protocolTypeVersion);
		this->lastUpdated(updatedTime);
		this->targetComponentURI(targetURI);
		this->componentsProtected(protectedComponents);
		this->requester(requester);
		this->requesterAuthentication(requesterAuthentication);
		this->responderAuthentication(responderAuthentication);
		this->responderVerificationStatus(status);

    log<level::INFO>("ComponentIntegrity Instance Created!");
}

ComponentIntegrity::~ComponentIntegrity()
{
    log<level::INFO>("ComponentIntegrity Instance Destroyed!");
}

std::tuple<sdbusplus::message::object_path, std::string,
    std::string, std::string, std::string, std::string>
    ComponentIntegrity::spdmGetSignedMeasurements(
        std::vector<uint32_t> measurementIndices,
        std::string nonce,
        uint32_t slotId) 
{
    sdbusplus::message::object_path
        certificate("/xyz/openbmc_project/certs/systems/system01/gf_cert1");
	std::string hashingAlg("SHA256");
	std::string pubKey("PUBKEY");
	std::string signedMeasurements("SIGNEDMEAUREMENTS");
	std::string signedAlg("SIGNINGALG");
	std::string version("VERSION_1.0");

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP) {
        /* Port number 4194 for SPDM */
        platform_client_routine(TCP_SPDM_PLATFORM_PORT);
    }
    else {
        platform_client_routine(DEFAULT_SPDM_PLATFORM_PORT);
    }

    printf("Client stopped\n");

    close_pcap_packet_file();

	// TODO set up SPDM channel and do GetMeasurements
	auto response = make_tuple(certificate, hashingAlg, pubKey,
                               signedMeasurements, signedAlg, version);
    return response;
}

} // namespace component_integrity
