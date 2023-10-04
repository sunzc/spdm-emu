#ifdef USE_SPDM_EMU
/**
 * For emulation, it is setting up a socket connection with responder.
 */
bool set_up_spdm_connection_emu(spdm_conn_t *spdm_conn,
    uint16_t port_number)
{
    bool result;
    uint32_t response;
    size_t response_size;
    libspdm_return_t status;

    if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP &&
        spdm_conn->m_use_tcp_handshake == SOCKET_TCP_HANDSHAKE) {
        spdm_conn->m_socket = CreateSocketAndHandShake(&spdm_conn->platform_socket, port_number);
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
        result = init_client(&spdm_conn->platform_socket, port_number);
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
        status = pci_doe_init_requester ();
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            printf("pci_doe_init_requester - %x\n", (uint32_t)status);
            goto done;
        }
    }

    spdm_conn->m_spdm_context = spdm_client_init();
    if (spdm_conn->m_spdm_context == NULL) {
        goto done;
    }

    return true; 

done:
    response_size = 0;
    result = communicate_platform_data(
        spdm_conn->m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - spdm_conn->m_exe_mode,
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

bool tear_down_spdm_connection_emu(spdm_conn_t *spdm_conn)
{
    bool result;
    uint32_t response;
    size_t response_size;

    response_size = 0;
    result = communicate_platform_data(
        spdm_conn->m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - spdm_conn->m_exe_mode,
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

    return true;
}

#endif
