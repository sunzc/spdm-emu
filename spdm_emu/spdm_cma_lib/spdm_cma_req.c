#include "spdm_cma_req.h"
#include "spdm_cma_req_internal.h"
//
/* need by libspdm/os_stub/spdm_device_secret_lib_sample/lib.c */
void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x", buffer[index]);
    }
}

/* support reading local certificates */
bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size)
{
    FILE *fp_in;
    size_t temp_result;

    if ((fp_in = fopen(file_name, "rb")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        *file_data = NULL;
        return false;
    }

    fseek(fp_in, 0, SEEK_END);
    *file_size = ftell(fp_in);
    if (*file_size == -1) {
        printf("Unable to get the file size %s\n", file_name);
        *file_data = NULL;
        fclose(fp_in);
        return false;
    }

    *file_data = (void *)malloc(*file_size);
    if (NULL == *file_data) {
        printf("No sufficient memory to allocate %s\n", file_name);
        fclose(fp_in);
        return false;
    }

    fseek(fp_in, 0, SEEK_SET);
    temp_result = fread(*file_data, 1, *file_size, fp_in);
    if (temp_result != *file_size) {
        printf("Read input file error %s", file_name);
        free((void *)*file_data);
        fclose(fp_in);
        return false;
    }

    fclose(fp_in);

    return true;
}

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size)
{
    FILE *fp_out;

    if ((fp_out = fopen(file_name, "w+b")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        return false;
    }

    if (file_size != 0) {
        if ((fwrite(file_data, 1, file_size, fp_out)) != file_size) {
            printf("Write output file error %s\n", file_name);
            fclose(fp_out);
            return false;
        }
    }

    fclose(fp_out);

    return true;
}

bool spdm_cma_calculate_l1l2_with_msg_log(libspdm_context_t *spdm_context,
                            void *log_msg_buffer,
                            size_t buffer_size,
                            libspdm_l1l2_managed_buffer_t *l1l2);

void dump_data(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x ", buffer[index]);
    }
}

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, void **msg_buf_ptr)
{
    spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
    printf("%s context:%p, conn:%p\n", __func__, context, conn);
    LIBSPDM_ASSERT (conn != NULL);
    LIBSPDM_ASSERT (!conn->m_send_receive_buffer_acquired);
    *msg_buf_ptr = conn->m_send_receive_buffer;
    libspdm_zero_mem (conn->m_send_receive_buffer, sizeof(conn->m_send_receive_buffer));
    conn->m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr)
{
    spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
    LIBSPDM_ASSERT (conn != NULL);
    LIBSPDM_ASSERT (conn->m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == conn->m_send_receive_buffer);
    conn->m_send_receive_buffer_acquired = false;
    return;
}

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr)
{
    spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
    LIBSPDM_ASSERT (conn != NULL);
    LIBSPDM_ASSERT (!conn->m_send_receive_buffer_acquired);
    *msg_buf_ptr = conn->m_send_receive_buffer;
    libspdm_zero_mem (conn->m_send_receive_buffer, sizeof(conn->m_send_receive_buffer));
    conn->m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr)
{
    spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
    LIBSPDM_ASSERT (conn != NULL);
    LIBSPDM_ASSERT (conn->m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == conn->m_send_receive_buffer);
    conn->m_send_receive_buffer_acquired = false;
    return;
}

/* PCI DOE as transport layer */
libspdm_return_t pci_doe_init_requester(spdm_conn_t *spdm_conn)
{
    pci_doe_data_object_protocol_t data_object_protocol[6];
    size_t data_object_protocol_size;
    libspdm_return_t status;
    uint32_t index;

    data_object_protocol_size = sizeof(data_object_protocol);
    /* TODO for emulation, pci_doe_discovery first parameter is spdm_conn;
     * for real device, it should be pci_doe_context */
    status =
        pci_doe_discovery (spdm_conn, data_object_protocol, &data_object_protocol_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    for (index = 0; index < data_object_protocol_size/sizeof(pci_doe_data_object_protocol_t);
         index++) {
        printf("DOE(0x%x) VendorId-0x%04x, DataObjectType-0x%02x\n",
               index, data_object_protocol[index].vendor_id,
               data_object_protocol[index].data_object_type);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

void *spdm_client_init(spdm_conn_t *spdm_conn)
{
    void *spdm_context;
    libspdm_return_t status;
    bool res;
    void *data;
    void *data1;
    size_t data_size;
    size_t data1_size;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    void *hash;
    void *hash1;
    size_t hash_size;
    size_t hash1_size;
    const uint8_t *root_cert;
    const uint8_t *root_cert1;
    size_t root_cert_size;
    size_t root_cert1_size;
    spdm_version_number_t spdm_version;
    size_t scratch_buffer_size;
    uint32_t responder_capabilities_flag;

    printf("context_size - 0x%x\n", (uint32_t)libspdm_get_context_size());

    spdm_conn->m_spdm_context = (void *)malloc(libspdm_get_context_size());
    if (spdm_conn->m_spdm_context == NULL) {
        return NULL;
    }
    spdm_context = spdm_conn->m_spdm_context;
    /**
     * linking conn to context so that device io functions can find
     * per-connection resources via context.
     */
    libspdm_init_context(spdm_context);
    ((libspdm_context_t *)spdm_context)->conn = spdm_conn;
    printf("%s context:%p, conn:%p\n", __func__, spdm_context, spdm_conn);

    /**
     * To handle real device, send/recieve functions are specified here.
     */
    libspdm_register_device_io_func(spdm_context, spdm_device_send_message,
                                    spdm_device_receive_message);

    if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message);
    } else if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_pci_doe_encode_message,
            libspdm_transport_pci_doe_decode_message);
    } else if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_TCP) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_tcp_encode_message,
            libspdm_transport_tcp_decode_message);
    } else if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            0,
            0,
            spdm_transport_none_encode_message,
            spdm_transport_none_decode_message);
    } else {
        free(spdm_conn->m_spdm_context);
        spdm_conn->m_spdm_context = NULL;
        return NULL;
    }
    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_SENDER_BUFFER_SIZE,
                                        LIBSPDM_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(spdm_context);
    spdm_conn->m_scratch_buffer = (void *)malloc(scratch_buffer_size);
    if (spdm_conn->m_scratch_buffer == NULL) {
        free(spdm_conn->m_spdm_context);
        spdm_conn->m_spdm_context = NULL;
        return NULL;
    }
    libspdm_set_scratch_buffer (spdm_context, spdm_conn->m_scratch_buffer, scratch_buffer_size);

    if (!libspdm_check_context(spdm_context))
    {
        free(spdm_conn->m_spdm_context);
        spdm_conn->m_spdm_context = NULL;
        return NULL;
    }

    if (spdm_conn->m_use_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = spdm_conn->m_use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdm_version, sizeof(spdm_version));
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    data8 = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));
    data32 = spdm_conn->m_use_requester_capability_flags;
    if (spdm_conn->m_use_slot_id == 0xFF) {
        data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    }
    if (spdm_conn->m_use_capability_flags != 0) {
        data32 = spdm_conn->m_use_capability_flags;
        spdm_conn->m_use_requester_capability_flags = spdm_conn->m_use_capability_flags;
    }
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    data8 = spdm_conn->m_support_measurement_spec;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = spdm_conn->m_support_asym_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = spdm_conn->m_support_hash_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = spdm_conn->m_support_dhe_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = spdm_conn->m_support_aead_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = spdm_conn->m_support_req_asym_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, sizeof(data16));
    data16 = spdm_conn->m_support_key_schedule_algo;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));
    data8 = spdm_conn->m_support_other_params_support;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));

    /**
     * zhichuang@: 
     * TODO: Assuming no load/save of negotiated state.
     * init will do VCA; Version only is for preshared
     * key where init only do V(ersion).
     */
    status = libspdm_init_connection(
        spdm_context,
        (spdm_conn->m_exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("libspdm_init_connection - 0x%x\n", (uint32_t)status);
        free(spdm_conn->m_spdm_context);
        spdm_conn->m_spdm_context = NULL;
        return NULL;
    }

    if (spdm_conn->m_use_version == 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
        data_size = sizeof(spdm_version);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                         &spdm_version, &data_size);
        spdm_conn->m_use_version = spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT;
    }

    /*get responder_capabilities_flag*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, &data_size);
    responder_capabilities_flag = data32;

    /*change m_exe_connection base on responder/requester supported capabilities*/
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP & responder_capabilities_flag) == 0) {
        spdm_conn->m_exe_connection &= ~EXE_CONNECTION_DIGEST;
        spdm_conn->m_exe_connection &= ~EXE_CONNECTION_CERT;
    }
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP & responder_capabilities_flag) == 0) {
        spdm_conn->m_exe_connection &= ~EXE_CONNECTION_CHAL;
    }
    if ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP & responder_capabilities_flag) == 0) {
        spdm_conn->m_exe_connection &= ~EXE_CONNECTION_MEAS;
    }

    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter,
                     &data32, &data_size);
    LIBSPDM_ASSERT(data32 == LIBSPDM_CONNECTION_STATE_NEGOTIATED);

    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &data32, &data_size);
    spdm_conn->m_use_measurement_hash_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, &data_size);
    spdm_conn->m_use_asym_algo = data32;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, &data_size);
    spdm_conn->m_use_hash_algo = data32;
    data_size = sizeof(data16);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, &data_size);
    spdm_conn->m_use_req_asym_algo = data16;

    /**
     * zhichuang@: PUB_KEY_ID_CAP is a new capability introduced in SPDM-1.3
     * If set, it means for requester/responder, the pubkey is provisioned in
     * the requester/responder, no CERT capablity needed.
     */
    if ((spdm_conn->m_use_requester_capability_flags &
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0) {
        spdm_conn->m_use_slot_id = 0xFF;
    }
    if (spdm_conn->m_use_slot_id == 0xFF) {
        res = libspdm_read_responder_public_key(spdm_conn->m_use_asym_algo, &data, &data_size);
        if (res) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_PEER_PUBLIC_KEY,
                             &parameter, data, data_size);
            /* Do not free it.*/
        } else {
            printf("read_responder_public_key fail!\n");
            free(spdm_conn->m_spdm_context);
            spdm_conn->m_spdm_context = NULL;
            return NULL;
        }
        res = libspdm_read_requester_public_key(spdm_conn->m_use_req_asym_algo, &data, &data_size);
        if (res) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                             &parameter, data, data_size);
            /* Do not free it.*/
        } else {
            printf("read_requester_public_key fail!\n");
            free(spdm_conn->m_spdm_context);
            spdm_conn->m_spdm_context = NULL;
            return NULL;
        }
    } else {
        /**
         * zhichuang@: to verify the cert chain locally, we need to read the
         * responder root public cert and use it to verify the cert chain we
         * get from the responder.
         * TODO: why we have to do it twice with different API? The second
         * read of slot_id==1 will overide the first read.
         */
        res = libspdm_read_responder_root_public_certificate(spdm_conn->m_use_hash_algo,
                                                             spdm_conn->m_use_asym_algo,
                                                             &data, &data_size,
                                                             &hash, &hash_size);
        if (res) {
            libspdm_x509_get_cert_from_cert_chain(
                (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                &root_cert, &root_cert_size);
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                             &parameter, (void *)root_cert, root_cert_size);
            /* Do not free it.*/
        } else {
            printf("read_responder_root_public_certificate fail!\n");
            free(spdm_conn->m_spdm_context);
            spdm_conn->m_spdm_context = NULL;
            return NULL;
        }
        res = libspdm_read_responder_root_public_certificate_slot(1,
                                                                  spdm_conn->m_use_hash_algo,
                                                                  spdm_conn->m_use_asym_algo,
                                                                  &data1, &data1_size,
                                                                  &hash1, &hash1_size);
        if (res) {
            libspdm_x509_get_cert_from_cert_chain(
                (uint8_t *)data1 + sizeof(spdm_cert_chain_t) + hash1_size,
                data1_size - sizeof(spdm_cert_chain_t) - hash1_size, 0,
                &root_cert1, &root_cert1_size);
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                             &parameter, (void *)root_cert1, root_cert1_size);
            /* Do not free it.*/
        } else {
            printf("read_responder_root_public_certificate fail!\n");
            free(spdm_conn->m_spdm_context);
            spdm_conn->m_spdm_context = NULL;
            return NULL;
        }
    }

    /* TODO: omit MUT_AUTH mutual authentication for now */

    return spdm_conn->m_spdm_context;
}

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
                                          size_t *cert_len) {
    // Generic
    libspdm_return_t status;

    // SPDM protocol related
    void *context;
    uint8_t slot_mask;
    uint8_t slot_id = spdm_conn->m_use_slot_id;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t cert_chain_buffer_size;
    uint8_t index;

    // file ops
    size_t hash_size = 0;

    context = spdm_conn->m_spdm_context;

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)

    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    // Update slot_mask with Get Digest
    // TODO :Who will use the other_slot_id?
    status = libspdm_get_digest(context, NULL, &slot_mask,
                                total_digest_buffer);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    for (index = 1; index < SPDM_MAX_SLOT_COUNT; index++) {
        if ((slot_mask & (1 << index)) != 0) {
            spdm_conn->m_other_slot_id = index;
        }
    }

    cert_chain_buffer_size = cert_chain_size;

    //TODO: Currently, if slot_id != 0, we get cert from slot_id
    // if slot_id == 0, we get slot from slot id 0; if other_slot_id != 0,
    // we get cert from other_slot_id.
    if (slot_id != 0xFF) {
        printf("DBUG ONLY: slot_id:%u m_other_slot_id:%u \n", slot_id,
                                spdm_conn->m_other_slot_id);
        if (slot_id == 0) {
            status = libspdm_get_certificate(
                context, NULL, 0, &cert_chain_size, cert_chain);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
            if (spdm_conn->m_other_slot_id != 0) {
                cert_chain_size = cert_chain_buffer_size;
                libspdm_zero_mem(cert_chain, cert_chain_buffer_size);
                status = libspdm_get_certificate(
                    context, NULL, spdm_conn->m_other_slot_id, &cert_chain_size, cert_chain);
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
    } else {
        printf("ERROR: Unexpected slot_id:%u, no certificate!\n", slot_id);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    /**
     * Extract DER formatted cert data from spdm response.
     * cert_chain format
     * | Length(2) | Reserved(2) | RootHash(H) | Certificates |
     */
    hash_size = libspdm_get_hash_size(spdm_conn->m_use_hash_algo);

    // Debug print only
    printf("cert_chain:%p, der_cert:%p, hash_size:%lu, cert_size:%lu, first byte: %02x\n",
            cert_chain, cert_chain + 4 + hash_size, hash_size, cert_chain_size, cert_chain[4+hash_size]);

    if (cert_buf == NULL || cert_len == NULL || buf_len == 0 || cert_chain_size > buf_len) {
        printf("ERROR: cert can't fit in cert_buf! cert_buf: %p, cert_len:%p, buf_len:%lu, cert_chain_size:%lu\n",
                cert_buf, cert_len, buf_len, cert_chain_size);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    memcpy(cert_buf, cert_chain + 4 + hash_size, cert_chain_size - 4 - hash_size);

    /* set certs size */
    *cert_len = cert_chain_size - 4 - hash_size;
#endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * calculate l1l2 with external log buffer.
 */
bool spdm_cma_calculate_l1l2_with_msg_log(libspdm_context_t *spdm_context,
                            void *msg_log_buffer,
                            size_t buffer_size,
                            libspdm_l1l2_managed_buffer_t *l1l2)
{
    libspdm_return_t status;

    libspdm_init_managed_buffer(l1l2, sizeof(l1l2->buffer));

    if ((spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >
        SPDM_MESSAGE_VERSION_11) {

        /* Need append VCA since 1.2 script*/

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "message_a data :\n"));
        LIBSPDM_INTERNAL_DUMP_HEX(
            libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
            libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
        status = libspdm_append_managed_buffer(
            l1l2,
            libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
            libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "calculate l1l2 failed! append message_a error!"));
            return false;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "message_m data(msg log buf size: %lu):\n", buffer_size));
    LIBSPDM_INTERNAL_DUMP_HEX(
        msg_log_buffer,
        buffer_size);
    status = libspdm_append_managed_buffer(
        l1l2,
        msg_log_buffer,
        buffer_size);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "calculate l1l2 failed! append msg log buffer error!"));
        return false;
    }

    return true;
}

/**
 * Note, an external verifier may not trust the spdm requester running on BMC,
 * and would like to verify the L1L2 by themselves. That's why an externally
 * provided nonce is provided here.
 * libspdm_get_measurements() will do the verification of measurements
 * signature and clear the message_m buffer after internal verification. 
 * see library/spdm_requester_lib/libspdm_req_get_measurements.c#L452C9-L452C61.
 * To support external verifier, we need to record the measurements messages
 * by ourselve and build the l1l2 by ourselve, too.
 * Refer to libspdm/library/spdm_common_lib/libspdm_com_crypto_service.c#L195
 * for l1l2 calculation. We mimic it to calculate l1l2 based on our message
 * buffer.
 * This function is called by the dbus daemon to get signed measurements from
 * device. 
 * @slot_id: slot Id of the certificate to be used for signing the measurements.
 * @nonce: a 32 byte nonce.
 * @indices: an array of index for the measurement blocks to be measured. 
 * @indices_len: length of indices array. 
 */ 
libspdm_return_t spdm_cma_get_signed_measurements(spdm_conn_t *conn,
                size_t slot_id, uint8_t* nonce, size_t* indices, size_t indices_len) {
    void *context;
    libspdm_return_t status;

    uint8_t i;
    uint8_t number_of_block;
    uint32_t received_number_of_block;
    uint32_t one_measurement_record_length;
    uint8_t one_measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size = sizeof(opaque_data);

    /* log buffer for external verification */
    bool result;
    uint8_t msg_log_buffer[8 * LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE]; /* TODO: 32KB or ? */
    size_t log_buffer_size;


    if (!nonce || !indices || indices_len == 0 || slot_id < 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Unexpected parameters : %s\n", __func__));
        status = LIBSPDM_STATUS_INVALID_PARAMETER;
        return status;
    }

    context = conn->m_spdm_context;

    request_attribute = conn->m_use_measurement_attribute;

    /* initialize log buffer and start logging */
    libspdm_init_msg_log (context, msg_log_buffer, sizeof(msg_log_buffer));
    libspdm_set_msg_log_mode (context, LIBSPDM_MSG_LOG_MODE_ENABLE);

    /**
     * query the total number of blocks available and check whether the requested
     * indices are within the range.
     */ 
    status = libspdm_get_measurement(
        context, NULL, request_attribute,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
        conn->m_use_slot_id & 0xF, NULL, &number_of_block, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "get_total_number_of_measurements failed!\n"));
        goto done;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "number_of_block - 0x%x\n", number_of_block));
    received_number_of_block = 0;

    for (i = 0; i < indices_len; i++) {
        /**
         * check index range:
         *   0: reserved, see SPDM spec;
         *   1 - N: valid; 
         *   N+ : invalid.
         */
        if (indices[i] <= 0 && indices[i] > number_of_block) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ERR: indices[%u] = %u is out of range (1, .., #BLOCKS %u)\n",
                   i, indices[i], number_of_block));
            break;
        }

        /* 2. query measurement one by one
         * get signature in last message only.
         *
         * Note, according to SPDM Spec 1.2 & 1.3
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
            request_attribute = conn->m_use_measurement_attribute |
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
                &one_measurement_record_length, one_measurement_record,
                requester_nonce_in, requester_nonce, responder_nonce,
                opaque_data, &opaque_data_size);

 		    if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "get measurement with sig failed, i:%d, indices_len:%d!\n", i, indices_len));
 		        break;
 		    }

            // TODO : check opaque data.
            //  is opaque data used for transport layer to distinguish
            //  different application data stream? 
       	    //  assert(requester_nonce_in[index] == requester_nonce[index]);
       	    //  assert(opaque_data_size, strlen("libspdm"));
       	    //  assert(opaque_data == "libspdm");
        } else {
 			status = libspdm_get_measurement(
 			    context, NULL, request_attribute,
 			    indices[i], slot_id & 0xF, NULL, &number_of_block,
 			    &one_measurement_record_length, one_measurement_record);

 		    if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "get measurement failed, i:%d, indices_len:%d!\n", i, indices_len));
 		        break;
 		    }
        }

        received_number_of_block += 1;
    }

    if (received_number_of_block != indices_len) {
        status = LIBSPDM_STATUS_INVALID_STATE_PEER;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
            "get measurement failed! not receiving all blocks #block:%d, indices_len:%d!\n",
                received_number_of_block, indices_len));
        goto done;
    }

    /* get log size */
    log_buffer_size = libspdm_get_msg_log_size (context);

    result = spdm_cma_calculate_l1l2_with_msg_log(context,
                                                  msg_log_buffer,
                                                  log_buffer_size,
                                                  &conn->l1l2);
    if (!result) {
        status = LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "calculate l1l2 failed!"));
        goto done;
    }

    // Note, we can safely return here. All we need from get measurements is
    // the conn->l1l2 Log, which can be calculated from spdm_context.
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

    status = LIBSPDM_STATUS_SUCCESS;
done:
    /* stop logging */
    libspdm_reset_msg_log (context);

    return status;
}
