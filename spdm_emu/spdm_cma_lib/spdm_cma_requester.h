/**
 * TODO: License Statement
 *
 * This SPDM Requester Lib is designed to be used by both a real SPDM
 * Requester or an emulated SPDM Requester. A real SPDM Requester talks to
 * real devices acting as SPDM Responder; An emulated SPDM Requester talks to
 * an emulated SPDM Responder using SOCKET.
 *
 * For real SPDM Requester, depending on what transport layer protocol it
 * uses, it needs to register the corresponding transport layer data
 * send-and-receive handlers as well as device layer data send-and-receive
 * handlers.
 * 
 * This library is designed to be able to manage multiple SPDM connections
 * with multiple devices on the requester side. However, it is not required
 * for the responder side to support multiple SPDM connections. We also don't
 * support multiple SPDM connections with the same responder device.
 *
 * This library only support MEAUREMENTS/CERTIFICATES, it is not intended for
 * secure sessions, as indicated by "CMA" in the library name.
 *
 * We don't intend to support Windows platform for this use case.
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * Whether it is used for emulated or real SPDM connection is decided at
 * compile time with the following macro, comment it out when handling real
 * devices.
 */
#define USE_SPDM_EMU

#define MAX_MEASUREMENTS_BUF_SIZE       0x4000  /* TODO:16KB */

/**
 * struct spdm_connection manages connection with one device;
 * Each conn is associated with only one spdm_context. All the other "m_xxx"
 * variables are intermediate states cached by the connection.
 */
typedef struct spdm_connection {
    void *m_spdm_context;
    void *m_scratch_buffer;

    uint8_t m_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];

    /* MCTP support */
    void *m_mctp_context;

    /* PCIe DOE */
    void *pci_doe_context;

    /* each emulated conn is identified by the port number or the socket */
#ifdef USE_SPDM_EMU
    SOCKET platform_socket;
    SOCKET m_socket;
    uint16_t m_port;
    uint32_t m_exe_mode;
    uint32_t m_use_tcp_handshake;
#endif

    /* TODO: each connection should record its own transport/device layer handlers */
    uint32_t m_use_transport_layer;

    /* cached spdm states: alg, cert slot, etc. */
    uint32_t m_use_hash_algo;
    uint8_t m_use_slot_id;
    uint8_t m_other_slot_id;

    /* CMA L1L2 log buffer */
    uint8_t l1l2[MAX_MEASUREMENTS_BUF_SIZE];
    size_t l1l2_len;
} spdm_conn_t;

#ifdef USE_SPDM_EMU
SOCKET CreateSocketAndHandShake(SOCKET *sock, uint16_t port_number);
bool init_client(SOCKET *sock, uint16_t port);
bool communicate_platform_data(SOCKET socket, size_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               size_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer);

bool set_up_spdm_connection_emu(spdm_conn_t *spdm_conn, uint16_t port_number);
bool tear_down_spdm_connection_emu(spdm_conn_t *spdm_conn);
#endif

/* for PCI DOE only */
libspdm_return_t pci_doe_init_requester(void);

/* create a spdm context and initialize part of spdm_conn */
void *spdm_client_init(spdm_conn_t *spdm_conn);

/* connection management */
libspdm_return_t set_up_spdm_connection(spdm_conn_t *spdm_conn);
libspdm_return_t tear_down_spdm_connection(spdm_conn_t *spdm_conn);

/* SPDM context initialization cmds: Version|Capabilities|Algorithms */
libspdm_return_t spdm_cma_vca(spdm_conn_t *spdm_conn);

/**
 * Note, get certificate and store it in the file with name fname.
 * According to the SPDM spec, the cert is in DER format.
 * @fname: filename specified by the caller to store cert chain.
 */ 
libspdm_return_t spdm_cma_get_certificate(spdm_conn_t *spdm_conn, const char *fname);

/**
 * This function is called by the dbus daemon to get signed measurements from
 * device. 
 * @slot_id: slot Id of the certificate to be used for signing the measurements.
 * @nonce: a 32 byte nonce.
 * @indices: an array of index for the measurement blocks to be measured. 
 * @indices_len: length of indices array. 
 *
 * Note, L2 logged in spdm_conn->l1l2.
 */ 
libspdm_return_t spdm_cma_get_signed_measurements(spdm_conn_t *spdm_conn,
        size_t slot_id, uint8_t* nonce, size_t* indices, size_t indices_len);
