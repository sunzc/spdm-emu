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

#ifndef _SPDM_CMA_REQ_H_
#define _SPDM_CMA_REQ_H_

/* enable transcript support to enable log */
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT 1

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/spdm_transport_tcp_lib.h"
#include "library/spdm_transport_none_lib.h"

#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_crypt_lib.h"

#include "library/pci_doe_common_lib.h"
#include "library/pci_doe_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"

#include "os_include.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

/**
 * Whether it is used for emulated or real SPDM connection is decided at
 * compile time with the following macro, comment it out when handling real
 * devices.
 */
#define USE_SPDM_EMU

/* execution mode for socket command */
#ifdef USE_SPDM_EMU
#define EXE_MODE_SHUTDOWN 0
#define EXE_MODE_CONTINUE 1
#endif

/* transport layer */
#define SOCKET_TRANSPORT_TYPE_NONE 0x00
#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02
#define SOCKET_TRANSPORT_TYPE_TCP 0x03

/* CONNECTION CAP */
#define EXE_CONNECTION_VERSION_ONLY 0x1
#define EXE_CONNECTION_DIGEST 0x2
#define EXE_CONNECTION_CERT 0x4
#define EXE_CONNECTION_CHAL 0x8
#define EXE_CONNECTION_MEAS 0x10
#define EXE_CONNECTION_SET_CERT 0x20
#define EXE_CONNECTION_GET_CSR 0x40

#define LIBSPDM_TRANSPORT_HEADER_SIZE 64
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64

/* define common LIBSPDM_TRANSPORT_ADDITIONAL_SIZE. It should be the biggest one. */
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE \
    (LIBSPDM_TRANSPORT_HEADER_SIZE + LIBSPDM_TRANSPORT_TAIL_SIZE)

#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_NONE_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in NONE
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_TCP_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in TCP
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_PCI_DOE_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in PCI_DOE
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_MCTP_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in MCTP
#endif

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

/* Maximum size of a single SPDM message.
 * It matches DataTransferSize in SPDM specification. */
#define LIBSPDM_SENDER_DATA_TRANSFER_SIZE (LIBSPDM_SENDER_BUFFER_SIZE - \
                                           LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE (LIBSPDM_RECEIVER_BUFFER_SIZE - \
                                             LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_DATA_TRANSFER_SIZE LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE

#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
#endif

#define MAX_MEASUREMENTS_BUF_SIZE       0x4000  /* TODO:16KB */

/**
 * struct spdm_connection manages connection with one device;
 * Each conn is associated with only one spdm_context. All the other "m_xxx"
 * variables are intermediate states cached by the connection.
 */
typedef struct spdm_connection {
    /* spdm settings */
    uint8_t m_use_version;
    uint8_t m_use_secured_message_version;

    void *m_spdm_context;

    void *m_scratch_buffer;
    uint8_t m_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    uint8_t m_send_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    size_t m_send_receive_buffer_size;
    bool m_send_receive_buffer_acquired;

    /* transport layer context: PCIe-DOE, MCTP support */
    void *m_mctp_context;
    void *m_pci_doe_context;

    /* each emulated conn is identified by the port number or the socket */
#ifdef USE_SPDM_EMU
    uint16_t port_number;
    uint16_t m_port;
    SOCKET platform_socket;
    SOCKET m_socket;

    uint32_t m_use_tcp_handshake;
    uint32_t m_exe_mode;
#endif

    /* TODO: each connection should record its own transport/device layer handlers */
    uint32_t m_use_transport_layer;
    uint32_t m_exe_connection;

    /* pre-config of requester alg&cap*/
    uint32_t m_use_requester_capability_flags;
    uint32_t m_use_responder_capability_flags;
    uint32_t m_use_capability_flags;
    uint32_t m_use_peer_capability_flags;
    uint8_t m_use_basic_mut_auth;

    uint8_t m_use_measurement_summary_hash_type;
    uint8_t m_use_measurement_operation;
    uint8_t m_use_measurement_attribute;
    uint8_t m_support_measurement_spec;
    uint32_t m_support_measurement_hash_algo;

    uint32_t m_support_hash_algo;
    uint32_t m_support_asym_algo;
    uint16_t m_support_req_asym_algo;
    uint16_t m_support_dhe_algo;
    uint16_t m_support_aead_algo;
    uint16_t m_support_key_schedule_algo; 

    uint8_t m_support_other_params_support;

    uint8_t m_session_policy;
    uint8_t m_end_session_attributes;

    /* cached spdm states: alg, cert slot, etc. */
    uint8_t m_other_slot_id;
    uint8_t m_use_slot_id;
    uint8_t m_use_slot_count;

    uint32_t m_use_hash_algo;
    uint32_t m_use_measurement_hash_algo;
    uint32_t m_use_asym_algo;
    uint16_t m_use_req_asym_algo;

    /* L1L2 log buffer */
    libspdm_l1l2_managed_buffer_t l1l2;
} spdm_conn_t;

/* debug helper function */
void dump_data(const uint8_t *buffer, size_t buffer_size);

/* manage spdm connection */
void preconfig_spdm_connection(spdm_conn_t *spdm_conn);
bool set_up_spdm_connection(spdm_conn_t *spdm_conn);
bool tear_down_spdm_connection(spdm_conn_t *spdm_conn);

/* for PCI DOE only */
libspdm_return_t pci_doe_init_requester(spdm_conn_t *spdm_conn);

/* create a spdm context and initialize part of spdm_conn */
void *spdm_client_init(spdm_conn_t *spdm_conn);

/**
 * This function is called by the dbus daemon to get certificate from
 * device, according to SPDM spec, the cert from spdm responder is in DER
 * format.
 * @spdm_conn: spdm connection;
 * @cert_buf: buffer to hold der format cert;
 * @buf_len: buffer length, check if the coming cert can fit in the buffer;
 * @cert_len: set the actual length of cert;
 * @return: status: error if can't get cert or cert can't fit in cert_buf;
 */ 
libspdm_return_t spdm_cma_get_certificate(spdm_conn_t *spdm_conn,
                                          uint8_t *cert_buf,
                                          size_t buf_len,
                                          size_t *cert_len);

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

#endif
