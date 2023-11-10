/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/


#include "command.h"
#include "spdm_cma_req.h"
/* device IO related functions */
#include "spdm_cma_req_internal.h"

bool read_bytes(const SOCKET socket, uint8_t *buffer,
                uint32_t number_of_bytes);
bool create_socket(uint16_t port_number, SOCKET *listen_socket);
SOCKET CreateSocketAndHandShake(SOCKET *sock, uint16_t port_number);
bool init_client(SOCKET *sock, uint16_t port);
bool communicate_platform_data(spdm_conn_t *conn, SOCKET socket, uint32_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               uint32_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer);

#ifdef _MSC_VER
struct in_addr m_ip_address = { { { 127, 0, 0, 1 } } };
#else
struct in_addr m_ip_address = { 0x0100007F };
#endif

bool init_client(SOCKET *sock, uint16_t port)
{
    SOCKET client_socket;
    struct sockaddr_in server_addr;
    int32_t ret_val;

#ifdef _MSC_VER
    WSADATA ws;
    if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
        printf("Init Windows socket Failed - %x\n", WSAGetLastError());
        return false;
    }
#endif

    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket == INVALID_SOCKET) {
        printf("Create socket Failed - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return false;
    }

    server_addr.sin_family = AF_INET;
    libspdm_copy_mem(&server_addr.sin_addr.s_addr, sizeof(struct in_addr), &m_ip_address,
                     sizeof(struct in_addr));
    server_addr.sin_port = htons(port);
    libspdm_zero_mem(server_addr.sin_zero, sizeof(server_addr.sin_zero));

    ret_val = connect(client_socket, (struct sockaddr *)&server_addr,
                      sizeof(server_addr));
    if (ret_val == SOCKET_ERROR) {
        printf("Connect Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        closesocket(client_socket);
        return false;
    }

    printf("connect success!\n");

    *sock = client_socket;
    return true;
}

bool create_socket(uint16_t port_number, SOCKET *listen_socket)
{
    struct sockaddr_in my_address;
    int32_t res;

    /* Initialize Winsock*/
#ifdef _MSC_VER
    WSADATA ws;
    res = WSAStartup(MAKEWORD(2, 2), &ws);
    if (res != 0) {
        printf("WSAStartup failed with error: %d\n", res);
        return false;
    }
#endif

    *listen_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (INVALID_SOCKET == *listen_socket) {
        printf("Cannot create server listen socket.  Error is 0x%x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return false;
    }

    /* When the program stops unexpectedly the used port will stay in the TIME_WAIT
     * state which prevents other programs from binding to this port until a timeout
     * triggers. This timeout may be 30s to 120s. In this state the responder cannot
     * be restarted since it cannot bind to its port.
     * To prevent this SO_REUSEADDR is applied to the socket which allows the
     * responder to bind to this port even if it is still in the TIME_WAIT state.*/
    if (setsockopt(*listen_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        printf("Cannot configure server listen socket.  Error is 0x%x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        closesocket(*listen_socket);
        return false;
    }

    libspdm_zero_mem(&my_address, sizeof(my_address));
    my_address.sin_port = htons((short)port_number);
    my_address.sin_family = AF_INET;

    res = bind(*listen_socket, (struct sockaddr *)&my_address,
               sizeof(my_address));
    if (res == SOCKET_ERROR) {
        printf("Bind error.  Error is 0x%x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        closesocket(*listen_socket);
        return false;
    }

    res = listen(*listen_socket, 3);
    if (res == SOCKET_ERROR) {
        printf("Listen error.  Error is 0x%x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        closesocket(*listen_socket);
        return false;
    }

    return true;
}

SOCKET CreateSocketAndHandShake(SOCKET *sock, uint16_t port_number) {
    bool result;
    struct sockaddr_in peer_address;
    uint32_t length;
    char buffer[INET_ADDRSTRLEN];
    uint8_t handshake_buf[TCP_HANDSHAKE_BUFFER_SIZE];
    tcp_spdm_binding_header_t *tcp_message_header;
    SOCKET requester_socket, incoming_socket;

    result = create_socket(port_number, &requester_socket);
    if (!result) {
        printf("Create platform service socket fail\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    printf("Platform server listening on port %d\n", port_number);
    length = sizeof(peer_address);
    incoming_socket = accept(requester_socket, (struct sockaddr *)&peer_address,
                             (socklen_t *)&length);
    if (incoming_socket == INVALID_SOCKET) {
        closesocket(requester_socket);
        printf("Accept error.  Error is 0x%x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    inet_ntop( AF_INET, &peer_address.sin_addr, buffer, sizeof( buffer ));
    printf("Connected to peer at: %s\n", buffer);

    libspdm_zero_mem(handshake_buf, TCP_HANDSHAKE_BUFFER_SIZE);
    result = read_bytes(incoming_socket, handshake_buf, TCP_HANDSHAKE_BUFFER_SIZE);
    if(!result) {
        closesocket(requester_socket);
        closesocket(incoming_socket);
        printf("Failed reading handshake data\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    tcp_message_header = (tcp_spdm_binding_header_t *) &handshake_buf;
    if(tcp_message_header->message_type != TCP_MESSAGE_TYPE_HANDSHAKE_REQUEST ||
       tcp_message_header->payload_length != TCP_HANDSHAKE_BUFFER_SIZE - 2) {
        closesocket(requester_socket);
        closesocket(incoming_socket);
        printf("Failed validating handshake data\n");
#ifdef _MSC_VER
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }

    *sock = requester_socket;
    return incoming_socket;
}

/**
 * Read number of bytes data in blocking mode.
 *
 * If there is no enough data in socket, this function will wait.
 * This function will return if enough data is read, or socket error.
 **/
bool read_bytes(const SOCKET socket, uint8_t *buffer,
                uint32_t number_of_bytes)
{
    int32_t result;
    uint32_t number_received;

    number_received = 0;
    while (number_received < number_of_bytes) {
        result = recv(socket, (char *)(buffer + number_received),
                      number_of_bytes - number_received, 0);
        if (result == -1) {
            printf("Receive error - 0x%x\n",
#ifdef _MSC_VER
                   WSAGetLastError()
#else
                   errno
#endif
                   );
            return false;
        }
        if (result == 0) {
            return false;
        }
        number_received += result;
    }
    return true;
}

bool read_data32(const SOCKET socket, uint32_t *data)
{
    bool result;

    result = read_bytes(socket, (uint8_t *)data, sizeof(uint32_t));
    if (!result) {
        return result;
    }
    *data = ntohl(*data);
    return true;
}

/**
 * Read multiple bytes in blocking mode.
 *
 * The length is presented as first 4 bytes in big endian.
 * The data follows the length.
 *
 * If there is no enough data in socket, this function will wait.
 * This function will return if enough data is read, or socket error.
 **/
bool read_multiple_bytes(const SOCKET socket, uint8_t *buffer,
                         uint32_t *bytes_received,
                         uint32_t max_buffer_length)
{
    uint32_t length;
    bool result;

    result = read_data32(socket, &length);
    if (!result) {
        return result;
    }
    printf("Platform port Receive size: ");
    length = ntohl(length);
    dump_data((uint8_t *)&length, sizeof(uint32_t));
    printf("\n");
    length = ntohl(length);

    *bytes_received = length;
    if (*bytes_received > max_buffer_length) {
        printf("buffer too small (0x%x). Expected - 0x%x\n",
               max_buffer_length, *bytes_received);
        return false;
    }
    if (length == 0) {
        return true;
    }
    result = read_bytes(socket, buffer, length);
    if (!result) {
        return result;
    }
    printf("Platform port Receive buffer:\n    ");
    dump_data(buffer, length);
    printf("\n");

    return true;
}

bool receive_platform_data(spdm_conn_t *conn, const SOCKET socket, uint32_t *command,
                           uint8_t *receive_buffer,
                           size_t *bytes_to_receive)
{
    bool result;
    uint32_t response;
    uint32_t transport_type;
    uint32_t bytes_received;

    result = read_data32(socket, &response);
    if (!result) {
        return result;
    }
    *command = response;
    printf("Platform port Receive command: ");
    response = ntohl(response);
    dump_data((uint8_t *)&response, sizeof(uint32_t));
    printf("\n");

    result = read_data32(socket, &transport_type);
    if (!result) {
        return result;
    }
    printf("Platform port Receive transport_type: ");
    transport_type = ntohl(transport_type);
    dump_data((uint8_t *)&transport_type, sizeof(uint32_t));
    printf("\n");
    transport_type = ntohl(transport_type);
    if (transport_type != conn->m_use_transport_layer) {
        printf("transport_type mismatch\n");
        return false;
    }

    bytes_received = 0;
    result = read_multiple_bytes(socket, receive_buffer, &bytes_received,
                                 (uint32_t)*bytes_to_receive);
    if (!result) {
        return result;
    }
    if (bytes_received > (uint32_t)*bytes_to_receive) {
        return false;
    }
    *bytes_to_receive = bytes_received;

    return result;
}

/**
 * Write number of bytes data in blocking mode.
 *
 * This function will return if data is written, or socket error.
 **/
bool write_bytes(const SOCKET socket, const uint8_t *buffer,
                 uint32_t number_of_bytes)
{
    int32_t result;
    uint32_t number_sent;

    number_sent = 0;
    while (number_sent < number_of_bytes) {
        result = send(socket, (char *)(buffer + number_sent),
                      number_of_bytes - number_sent, 0);
        if (result == -1) {
#ifdef _MSC_VER
            if (WSAGetLastError() == 0x2745) {
                printf("Client disconnected\n");
            } else {
#endif
            printf("Send error - 0x%x\n",
#ifdef _MSC_VER
                   WSAGetLastError()
#else
                   errno
#endif
                   );
#ifdef _MSC_VER
        }
#endif
            return false;
        }
        number_sent += result;
    }
    return true;
}

bool write_data32(const SOCKET socket, uint32_t data)
{
    data = htonl(data);
    return write_bytes(socket, (uint8_t *)&data, sizeof(uint32_t));
}

/**
 * Write multiple bytes.
 *
 * The length is presented as first 4 bytes in big endian.
 * The data follows the length.
 **/
bool write_multiple_bytes(const SOCKET socket, const uint8_t *buffer,
                          uint32_t bytes_to_send)
{
    bool result;

    result = write_data32(socket, bytes_to_send);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit size: ");
    bytes_to_send = htonl(bytes_to_send);
    dump_data((uint8_t *)&bytes_to_send, sizeof(uint32_t));
    printf("\n");
    bytes_to_send = htonl(bytes_to_send);

    result = write_bytes(socket, buffer, bytes_to_send);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit buffer:\n    ");
    dump_data(buffer, bytes_to_send);
    printf("\n");
    return true;
}

bool send_platform_data(spdm_conn_t *conn, const SOCKET socket, uint32_t command,
                        const uint8_t *send_buffer, size_t bytes_to_send)
{
    bool result;
    uint32_t request;
    uint32_t transport_type;

    request = command;
    result = write_data32(socket, request);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit command: ");
    request = htonl(request);
    dump_data((uint8_t *)&request, sizeof(uint32_t));
    printf("\n");

    result = write_data32(socket, conn->m_use_transport_layer);
    if (!result) {
        return result;
    }
    printf("Platform port Transmit transport_type: ");
    transport_type = ntohl(conn->m_use_transport_layer);
    dump_data((uint8_t *)&transport_type, sizeof(uint32_t));
    printf("\n");

    result = write_multiple_bytes(socket, send_buffer,
                                  (uint32_t)bytes_to_send);
    if (!result) {
        return result;
    }

    return true;
}


bool communicate_platform_data(spdm_conn_t *conn, SOCKET socket, uint32_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               uint32_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer)
{
    bool result;

    result =
        send_platform_data(conn, socket, command, send_buffer, bytes_to_send);
    if (!result) {
        printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return result;
    }

    result = receive_platform_data(conn, socket, response, receive_buffer,
                                   bytes_to_receive);
    if (!result) {
        printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return result;
    }
    return result;
}

libspdm_return_t spdm_device_send_message(void *spdm_context,
                                          size_t request_size, const void *request,
                                          uint64_t timeout)
{
    bool result;
    spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;

    result = send_platform_data(spdm_conn, spdm_conn->m_socket, SOCKET_SPDM_COMMAND_NORMAL,
                                request, (uint32_t)request_size);
    if (!result) {
        printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_device_receive_message(void *spdm_context,
                                             size_t *response_size,
                                             void **response,
                                             uint64_t timeout)
{
    bool result;
    uint32_t command;
    spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;

    result = receive_platform_data(spdm_conn, spdm_conn->m_socket, &command, *response,
                                   response_size);
    if (!result) {
        printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Send and receive an DOE message
 *
 * @param request                       the PCI DOE request message, start from pci_doe_data_object_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the PCI DOE response message, start from pci_doe_data_object_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The request is sent and response is received.
 * @return ERROR                        The response is not received correctly.
 **/
 /**
  * TODO Note, for emulation the first parameter is spdm_conn; for real device,
  * it should be pci_doe_context
  */
libspdm_return_t pci_doe_send_receive_data(const void *conn,
                                           size_t request_size, const void *request,
                                           size_t *response_size, void *response)
{
    bool result;
    uint32_t response_code;
    spdm_conn_t *spdm_conn = (spdm_conn_t *)conn;

    result = communicate_platform_data(
        spdm_conn, spdm_conn->m_socket, SOCKET_SPDM_COMMAND_NORMAL,
        request, request_size,
        &response_code, response_size,
        response);
    if (!result) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

/* pre-config requester's version/cap/etc before setting up the spdm connection */
void preconfig_spdm_connection(spdm_conn_t *spdm_conn)
{
    /* SPDM Version */
    spdm_conn->m_use_version = 0;
    spdm_conn->m_use_secured_message_version = 0;

    /* SOCKET Execution Mode: Socket based EMU only */
    spdm_conn->port_number = DEFAULT_SPDM_PLATFORM_PORT;
    spdm_conn->m_exe_mode = EXE_MODE_SHUTDOWN;
    spdm_conn->m_use_transport_layer = SOCKET_TRANSPORT_TYPE_PCI_DOE;

    /* resource buffer status initlization */
    spdm_conn->m_send_receive_buffer_acquired = false;

    spdm_conn->m_exe_connection = (0 |
                             /* EXE_CONNECTION_VERSION_ONLY |*/
                             EXE_CONNECTION_DIGEST | EXE_CONNECTION_CERT |
                             EXE_CONNECTION_CHAL | EXE_CONNECTION_MEAS |
                             EXE_CONNECTION_SET_CERT | EXE_CONNECTION_GET_CSR | 0);

    spdm_conn->m_use_requester_capability_flags =
        (0 |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /* conflict with SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP */
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP |
         /* SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |    conflict with SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP   */
         0);

    spdm_conn->m_use_responder_capability_flags =
        (0 | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
         /* SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |    conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG   */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
         /* SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER |    conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT   */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP |
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
         /* SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP |    conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP   */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP |
         /* SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP | conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP */
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP | /* conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP */
         /* SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP | conflict with SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP */
         0);

    spdm_conn->m_use_capability_flags = 0;
    spdm_conn->m_use_peer_capability_flags = 0;
    /*
     * 0
     * 1
     */
    spdm_conn->m_use_basic_mut_auth = 1;

    /*
     * SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
     * SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
     * SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH
     */
    spdm_conn->m_use_measurement_summary_hash_type =
        SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;
    /*
     * SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,    one by one
     * SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS
     */
    spdm_conn->m_use_measurement_operation =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
    /*
     * 0
     * SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED
     */
    spdm_conn->m_use_measurement_attribute = 0;
    spdm_conn->m_use_slot_id = 0;
    spdm_conn->m_use_slot_count = 3;
    
    //spdm_conn->m_use_hash_algo;
    //spdm_conn->m_use_measurement_hash_algo;
    //spdm_conn->m_use_asym_algo;
    //spdm_conn->m_use_req_asym_algo;
    
    /*
     * SPDM_MEASUREMENT_SPECIFICATION_DMTF,
     */
    spdm_conn->m_support_measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    /*
     * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,
     * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,
     * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,
     * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
     * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
     * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
     * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
     */
    spdm_conn->m_support_measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    /*
     * SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
     * SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
     * SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
     */
    spdm_conn->m_support_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                   SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    /*
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
     */
    spdm_conn->m_support_asym_algo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    /*
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
     * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
     */
    spdm_conn->m_support_req_asym_algo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    /*
     * SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,
     * SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,
     * SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,
     * SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1,
     * SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
     * SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1,
     */
    spdm_conn->m_support_dhe_algo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048;
    /*
     * SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
     * SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,
     * SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
     */
    spdm_conn->m_support_aead_algo =
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
        SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    /*
     * SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,
     */
    spdm_conn->m_support_key_schedule_algo = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    /*
     * SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
     */
    spdm_conn->m_support_other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    
    spdm_conn->m_session_policy =
        SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_TERMINATION_POLICY_RUNTIME_UPDATE;
    
    spdm_conn->m_end_session_attributes =
        SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR;

    /* transport layer preconfig for socket-based emu */
    spdm_conn->m_use_tcp_handshake = SOCKET_TCP_NO_HANDSHAKE;
    spdm_conn->m_send_receive_buffer_acquired = false;

    return;
}

/**
 * For emulation, it is setting up a socket connection with responder.
 */
bool set_up_spdm_connection(spdm_conn_t *spdm_conn)
{
    bool result;
    uint32_t response;
    size_t response_size;
    libspdm_return_t status;

    if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
        spdm_conn->m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE) {
        spdm_conn->m_socket =
        CreateSocketAndHandShake(&spdm_conn->platform_socket, spdm_conn->port_number);
        if (spdm_conn->m_socket == INVALID_SOCKET) {
            printf("Create platform service socket fail\n");
#ifdef _MSC_VER
            WSACleanup();
#endif
            return false;
        }

        printf("Continuing with SPDM flow...\n");
    }
    else {
        result = init_client(&spdm_conn->platform_socket, spdm_conn->port_number);
        if (!result) {
#ifdef _MSC_VER
            WSACleanup();
#endif
            return false;
        }

        spdm_conn->m_socket = spdm_conn->platform_socket;
    }

    if (spdm_conn->m_use_transport_layer != SOCKET_TRANSPORT_TYPE_NONE) {
        response_size = sizeof(spdm_conn->m_receive_buffer);
        result = communicate_platform_data(
            spdm_conn,
            spdm_conn->m_socket,
            SOCKET_SPDM_COMMAND_TEST,
            (uint8_t *)"Client Hello!",
            sizeof("Client Hello!"), &response,
            &response_size, spdm_conn->m_receive_buffer);
        if (!result) {
            goto done;
        }
    }

    if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        status = pci_doe_init_requester (spdm_conn);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("pci_doe_init_requester - %x\n", (uint32_t)status);
            goto done;
        }
    }

    spdm_conn->m_spdm_context = spdm_client_init(spdm_conn);
    if (spdm_conn->m_spdm_context == NULL) {
        goto done;
    }

    return true; 

done:
    response_size = 0;
    result = communicate_platform_data(
        spdm_conn, spdm_conn->m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - spdm_conn->m_exe_mode,
        NULL, 0, &response, &response_size, NULL);

    if (spdm_conn->m_spdm_context != NULL) {
        libspdm_deinit_context(spdm_conn->m_spdm_context);
        free(spdm_conn->m_spdm_context);
        free(spdm_conn->m_scratch_buffer);
    }

    closesocket(spdm_conn->platform_socket);
    if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
        spdm_conn->m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE) {
        closesocket(spdm_conn->m_socket);
    }

#ifdef _MSC_VER
    WSACleanup();
#endif

    return false;
}

bool tear_down_spdm_connection(spdm_conn_t *spdm_conn)
{
    bool result;
    uint32_t response;
    size_t response_size;

    response_size = 0;
    result = communicate_platform_data(
        spdm_conn, spdm_conn->m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - spdm_conn->m_exe_mode,
        NULL, 0, &response, &response_size, NULL);

    if (spdm_conn->m_spdm_context != NULL) {
        libspdm_deinit_context(spdm_conn->m_spdm_context);
        free(spdm_conn->m_spdm_context);
        free(spdm_conn->m_scratch_buffer);
    }

    closesocket(spdm_conn->platform_socket);
    if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
        spdm_conn->m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE) {
        closesocket(spdm_conn->m_socket);
    }

#ifdef _MSC_VER
    WSACleanup();
#endif

    return result;
}
