#include "config_site_sample.h"

#define PJ_IOQUEUE_MAX_HANDLES (65535)
/**
 * Increase max timed out entires above PJ_IOQUEUE_MAX_EVENTS_IN_SINGLE_POLL to ensure we don't suffer from timer starvation.
 */
#define PJSIP_MAX_TIMED_OUT_ENTRIES (128)
/**
 * Increase the TCP transport backlog to cope with temporary TCP connection overload.
 */
#define PJSIP_TCP_TRANSPORT_BACKLOG 32
/**
 * Increase the size of the transport manager's hash table size (must be 2^n-1) - we expect many thousands of connections.
 */
#define PJSIP_TPMGR_HTABLE_SIZE	32767
/**
 * Disable TCP keep-alives.  These make sense for the client to send to us, but not the other way round.
 */
#define PJSIP_TCP_KEEP_ALIVE_INTERVAL 0
/**
 * Increase the maximum packet length. INVITEs for video with
 * STUN/TURN can be very large due to the many alternatives offered,
 * and we mustn't drop them.  This can be set as high as 65535,
 * but packets of that size are almost certainly pathological.
 */
#define PJSIP_MAX_PKT_LEN 8000
/**
 * Disable alias parameter on Via headers.  This is a new feature in PJSIP
 * that is enabled by default, but causes interop problems with some clients.
 */
#define PJSIP_REQ_HAS_VIA_ALIAS PJ_FALSE
