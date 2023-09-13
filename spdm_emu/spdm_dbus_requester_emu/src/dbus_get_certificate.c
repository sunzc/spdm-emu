#include "dbus_get_certificate.h"
#include <stdio.h>
#include <stdlib.h>
//#include "spdm_emu.h"
// socket based test only
#define LIBSPDM_TRANSPORT_HEADER_SIZE 64
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64

/* define common LIBSPDM_TRANSPORT_ADDITIONAL_SIZE. It should be the biggest one. */
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE \
    (LIBSPDM_TRANSPORT_HEADER_SIZE + LIBSPDM_TRANSPORT_TAIL_SIZE)

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

#define DEFAULT_SPDM_PLATFORM_PORT 2323
#define SOCKET_SPDM_COMMAND_TEST 0xDEAD
#define SOCKET_SPDM_COMMAND_SHUTDOWN 0xFFFE
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE

extern uint32_t m_exe_mode;
extern SOCKET m_socket;
extern uint32_t m_use_transport_layer;
extern uint32_t m_use_tcp_handshake;
extern uint8_t m_use_slot_id;
extern uint32_t m_use_hash_algo;
SOCKET CreateSocketAndHandShake(SOCKET *sock, uint16_t port_number);
bool init_client(SOCKET *sock, uint16_t port);
bool communicate_platform_data(SOCKET socket, size_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               size_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer);

// PCIE DOE
libspdm_return_t pci_doe_init_requester(void);

// SPDM Context
extern void *m_spdm_context;
extern uint8_t m_other_slot_id;
void *spdm_client_init(void);

void dump_certificate(uint8_t *cert, size_t len) {
    size_t i;

    printf("\n");
    for (i = 0; i < len; i++) {
        printf("%02x ", cert[i]);
    }
    printf("\n");
}

/* This function is called by the dbus daemon to get certificate from
 * device and store it in fname. Note, according to SPDM spec, the cert
 * is in DER format. */ 
libspdm_return_t dbus_get_certificate(const char *fname) {
    // Generic
    libspdm_return_t status;

    // Socket to emulate transport layer
    bool result;
    SOCKET platform_socket;
    size_t response;
    size_t response_size;

    // SPDM protocol related
    void *context;
    uint8_t slot_mask;
    uint8_t slot_id = m_use_slot_id;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t m_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_buffer_size;
    uint8_t index;

    // file ops
    size_t hash_size = 0;
    FILE *fptr;

    // Emulation only: using socket to connect Requester and Responder
    // To simplify emulation:
    //   ASSUME m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE
    //   ASSUME m_use_tcp_handshake == SOCKET_TCP_NO_HANDSHAKE
    //   ASSUME linux only, no microsoft windows support
    result = init_client(&platform_socket, DEFAULT_SPDM_PLATFORM_PORT);
    if (!result) {
        return false;
    }

    m_socket = platform_socket;

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

    // PCI DOE Set up
    status = pci_doe_init_requester ();
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("pci_doe_init_requester - %lx\n", (size_t)status);
        goto done;
    }

    // SPDM Requester Init
    m_spdm_context = spdm_client_init();
    if (m_spdm_context == NULL) {
        goto done;
    }

    context = m_spdm_context;

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)

    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    // Get Digest
    status = libspdm_get_digest(context, NULL, &slot_mask,
                                total_digest_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    for (index = 1; index < SPDM_MAX_SLOT_COUNT; index++) {
        if ((slot_mask & (1 << index)) != 0) {
            m_other_slot_id = index;
        }
    }

    cert_chain_buffer_size = cert_chain_size;

    if (slot_id != 0xFF) {
        printf("DBUG ONLY: slot_id:%u m_other_slot_id:%u \n", slot_id, m_other_slot_id);
        if (slot_id == 0) {
            status = libspdm_get_certificate(
                context, NULL, 0, &cert_chain_size, cert_chain);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
            if (m_other_slot_id != 0) {
                cert_chain_size = cert_chain_buffer_size;
                libspdm_zero_mem(cert_chain, cert_chain_buffer_size);
                status = libspdm_get_certificate(
                    context, NULL, m_other_slot_id, &cert_chain_size, cert_chain);
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    return status;
                }
            }
        } else {
            status = libspdm_get_certificate(
                context, NULL, slot_id, &cert_chain_size, cert_chain);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }
    }

    /**
     * cert_chain format
     * | Length(2) | Reserved(2) | RootHash(H) | Certificates |
     */
    hash_size = libspdm_get_hash_size(m_use_hash_algo); 
    fptr = fopen(fname, "wb");
    if(fptr == NULL) {
        printf("File open error! fname:%s\n", fname);
        status = LIBSPDM_STATUS_INVALID_PARAMETER;
        goto done;
    }

    printf("cert_chain:%p, der_cert:%p, hash_size:%lu, cert_size:%lu, first byte: %02x\n",cert_chain, cert_chain + 4 + hash_size, hash_size, cert_chain_size, cert_chain[4+hash_size]);
    fwrite(cert_chain + 4 + hash_size, sizeof(uint8_t), cert_chain_size - 4 - hash_size, fptr);

    printf("========== %s ===========\n",__func__);
    dump_certificate(cert_chain, cert_chain_size);

done:
    response_size = 0;
    result = communicate_platform_data(
        m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - m_exe_mode,
        NULL, 0, &response, &response_size, NULL);
    
    if (m_spdm_context != NULL) {
        libspdm_deinit_context(m_spdm_context);
        free(m_spdm_context);
    }
    
    closesocket(platform_socket);

    fclose(fptr);

    return LIBSPDM_STATUS_SUCCESS;
#endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/
}
