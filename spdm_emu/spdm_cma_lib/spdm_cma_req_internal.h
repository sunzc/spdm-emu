#ifndef _SPDM_CMA_REQ_COMMON_H_
#define _SPDM_CMA_REQ_COMMON_H_

/**
 * The interfaces listed here needs to be implemented in a device-specific
 * way, depending on whether it is using SOCKET to emulate a SPDM connection,
 * or using MCTP, or PCIe DOE as the transport layer.
 * 
 * The interfaces defined here are for internal use only.
 */

/* support read/write certs file */
bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size);


libspdm_return_t spdm_device_send_message(void *spdm_context,
                                          size_t request_size, const void *request,
                                          uint64_t timeout);
libspdm_return_t spdm_device_receive_message(void *spdm_context,
                                             size_t *response_size,
                                             void **response,
                                             uint64_t timeout);

/**
 * Send and receive an DOE message. Implement it only when you use PCIe DOE.
 *
 * @param request                       the PCI DOE request message, start from pci_doe_data_object_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the PCI DOE response message, start from pci_doe_data_object_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The request is sent and response is received.
 * @return ERROR                        The response is not received correctly.
 **/
libspdm_return_t pci_doe_send_receive_data(const void *spdm_context,
                                           size_t request_size, const void *request,
                                           size_t *response_size, void *response);

libspdm_return_t pci_doe_init_requester(spdm_conn_t *spdm_conn);
#endif
