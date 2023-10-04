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

/**
 * For emulation, it is setting up a socket connection with responder.
 * Note, for transport layer, it assumes PCI DOE and nitialize pci doe
 * requester. The last step is to initialize spdm context.
 */
libspdm_return_t set_up_device_connection()
{
    // Generic
    libspdm_return_t status;

    // Socket to emulate transport layer
    bool result;
    SOCKET platform_socket;
    size_t response;
    size_t response_size;

    // Emulation only: using socket to connect Requester and Responder
    // To simplify emulation:
    //   ASSUME m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE
    //   ASSUME m_use_tcp_handshake == SOCKET_TCP_NO_HANDSHAKE
    //   ASSUME linux only, no microsoft windows support
    result = init_client(&platform_socket, DEFAULT_SPDM_PLATFORM_PORT);
    if (!result) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
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
        status = LIBSPDM_STATUS_INVALID_STATE_LOCAL;
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
        status = LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        goto done;
    }

    return LIBSPDM_STATUS_SUCCESS;

done:
    response_size = 0;
    result = communicate_platform_data(
        m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - m_exe_mode,
        NULL, 0, &response, &response_size, NULL);
    
    if (m_spdm_context != NULL) {
        libspdm_deinit_context(m_spdm_context);
        free(m_spdm_context);
    }
    
    closesocket(m_socket);

    return status;
}

libspdm_return_t tear_down_device_connection()
{
    // Socket to emulate transport layer
    bool result;
    size_t response;
    size_t response_size;
    response_size = 0;

    result = communicate_platform_data(
        m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - m_exe_mode,
        NULL, 0, &response, &response_size, NULL);
    
    if (m_spdm_context != NULL) {
        libspdm_deinit_context(m_spdm_context);
        free(m_spdm_context);
    }
    
    closesocket(m_socket);

    return LIBSPDM_STATUS_SUCCESS;
}


/* This function is called by the dbus daemon to get certificate from
 * device and store it in fname. Note, according to SPDM spec, the cert
 * is in DER format. */ 
libspdm_return_t dbus_get_certificate(const char *fname) {
    // Generic
    libspdm_return_t status;

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

    context = m_spdm_context;

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)

    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    // Update slot_mask with Get Digest
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

    //TODO When slot_it != 0, should we create a certificate for each slot?
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
     * Extract DER formatted cert data from spdm response.
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

    // Debug print only
    printf("cert_chain:%p, der_cert:%p, hash_size:%lu, cert_size:%lu, first byte: %02x\n",
            cert_chain, cert_chain + 4 + hash_size, hash_size, cert_chain_size, cert_chain[4+hash_size]);

    // Only store the cert data.
    fwrite(cert_chain + 4 + hash_size, sizeof(uint8_t), cert_chain_size - 4 - hash_size, fptr);

    // printf("========== %s ===========\n",__func__);
    // dump_certificate(cert_chain, cert_chain_size);

    fclose(fptr);
#endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/

    return LIBSPDM_STATUS_SUCCESS;
}

// TODO: provide interface for dbus daemon to query about the meta data of the GET_MEAUREMENTS
// For example, SPDM Version | HashingAlgorithm | SigningAlgorithm | Certificate

/**
 * This function is called by the dbus daemon to get signed measurements from
 * device. 
 * @slot_id: slot Id of the certificate to be used for signing the measurements.
 * @nonce: a 32 byte nonce.
 * @indices: an array of index for the measurement blocks to be measured. 
 * @indices_len: length of indices array. 
 */ 
libspdm_return_t dbus_get_signed_measurements(size_t slot_id, uint8_t* nonce, size_t* indices, size_t indices_len) {
    void *context;
    libspdm_return_t status;

    uint8_t i;
    uint8_t number_of_blocks;
    uint8_t number_of_block;
    uint32_t one_measurement_record_length;
    uint8_t one_measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t all_measurement_records[8*LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE]; /* TODO: 32KB or ? */
    uint8_t request_attribute;
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size;

    if (!nonce || !indices || indices_len == 0 || slot_id < 0) {
        printf("Unexpected parameters : %s\n", __func__);
        status = LIBSPDM_STATUS_INVALID_PARAMETER;
        goto done;
    }

    context = m_spdm_context;

    request_attribute = m_use_measurement_attribute;

    /**
     * query the total number of blocks available and check whether the requested
     * indices are within the range.
     */ 
    status = libspdm_get_measurement(
        context, NULL, request_attribute,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
        m_use_slot_id & 0xF, NULL, &number_of_blocks, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "number_of_blocks - 0x%x\n",
                   number_of_blocks));
    received_number_of_block = 0;

    for (i = 0; i < indices_len; i++) {
        /* 1. check given index and make sure it is valid, index start from 1, 0 is reserved see SPDM spec. */
        if (indices[i] <= 0 && indices[i] > number_of_blocks) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ERR: indices[%u] = %u is out of range (1, .., #BLOCKS %u)\n",
                   i, indices[i], number_of_blocks));
            break;
        }

        /* 2. query measurement one by one
         * get signature in last message only.
         *
         * Note, according to SPDM Spec 1.3
         * (see https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.0.pdf, P116, L516)
         * Signature = SPDMsign(PrivKey, L1, "measurements signing");
         * Where L1/L2 = Concatenate(VCA, GET_MEASUREMENTS_REQUEST1, MEASUREMENTS_RESPONSE1, ...,
         *       GET_MEASUREMENTS_REQUESTn-1, MEASUREMENTS_RESPONSEn-1,
         *       GET_MEASUREMENTS_REQUESTn, MEASUREMENTS_RESPONSEn)
         * REQ1 - REQn-1 no signature required
         * REQn signature required
         * We return the whole L2 back to Notar for verification.
         */
        one_measurement_record_length = sizeof(one_measurement_record);
        if (i == indices_len - 1) {
            /* generate signature with designated nonce */
            request_attribute = m_use_measurement_attribute |
                                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

            /* initialize nonce */
            for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
                requester_nonce_in[index] = nonce[index];
                requester_nonce[index] = 0x00;
                responder_nonce[index] = 0x00;
            }

            status = libspdm_get_measurement_ex(
                context, NULL, request_attribute,
                indices[i], slot_id & 0xF, NULL, &number_of_block,
                &measurement_record_length, one_measurement_record,
                requester_nonce_in, requester_nonce, responder_nonce,
                opaque_data, &opaque_data_size);

            // TODO some check:
       	    //  assert(requester_nonce_in[index] == requester_nonce[index]);
       	    //  assert(opaque_data_size, strlen("libspdm"));
       	    //  assert(opaque_data == "libspdm");
        } else {
 			status = libspdm_get_measurement(
 			    context, NULL, request_attribute,
 			    indices[i], slot_id & 0xF, NULL, &number_of_block,
 			    &one_measurement_record_length, one_measurement_record);
        }

 		if (LIBSPDM_STATUS_IS_ERROR(status)) {
 		    continue;
 		}

        received_number_of_block += 1;
    }

    if (received_number_of_block != indices_len) {
        status = LIBSPDM_STATUS_INVALID_STATE_PEER;
        goto done;
    }

    // Note, we can safely return here. All we need from get measurements is
    // the L2 Log, which can be calculated from spdm_context.
    //
	// See library//spdm_requester_lib/libspdm_req_get_measurements.c on how to get everything for
	//   component_integrity.cpp 
    //      ComponentIntegrity::spdmGetSignedMeasurements(
    //          std::vector<size_t> measurementIndices,
    //          std::string nonce,
    //          size_t slotId)
	// For example:
	//   pubkey: spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key;
	//   l1l2:l1l2_buffer = libspdm_get_managed_buffer(&l1l2);
	//   Signature:
	//   SPDM_VERSION: spdm_context->connection_info.version
    //   SIGNALG: spdm_context->connection_info.algorithm.base_asym_algo
    //   HASHALG: spdm_context->connection_info.algorithm.base_hash_algo
	//
	// See library//spdm_requester_lib/libspdm_req_get_measurements.c L336 on how to extract signature from response
	//     measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
	//     measurement_record_data = (void *)(spdm_response + 1);
    //	   ptr = measurement_record_data + measurement_record_data_length;
    //	   nonce = ptr;
    //	   LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "nonce (0x%x) - ", SPDM_NONCE_SIZE));
    //	   LIBSPDM_INTERNAL_DUMP_DATA(nonce, SPDM_NONCE_SIZE);
    //	   LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    //     ptr += SPDM_NONCE_SIZE;
    //     opaque_length = libspdm_read_uint16((const uint8_t *)ptr);
    //     ptr += sizeof(uint16_t);
    //     ptr += opaque_length;
    //     signature = ptr;

    return LIBSPDM_STATUS_SUCCESS;

done:
    return status;
}
