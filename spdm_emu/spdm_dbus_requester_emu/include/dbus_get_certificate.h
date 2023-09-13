#ifndef __SPDM_DBUS_GET_CERTIFICATE_H__
#define __SPDM_DBUS_GET_CERTIFICATE_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_none_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/spdm_transport_tcp_lib.h"
#include "library/mctp_requester_lib.h"
#include "library/pci_doe_requester_lib.h"
#include "library/pci_ide_km_requester_lib.h"
#include "library/pci_tdisp_requester_lib.h"
#include "library/cxl_ide_km_requester_lib.h"

#include "os_include.h"
#include "stdio.h"

libspdm_return_t dbus_get_certificate(const char *fname);

#endif
