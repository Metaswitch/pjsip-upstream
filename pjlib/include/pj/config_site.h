/**
 * @file config_site.h
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

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
 * Disable alias parameter on Via headers.  This is a new feature in PJSIP
 * that is enabled by default, but causes interop problems with some clients.
 */
#define PJSIP_REQ_HAS_VIA_ALIAS PJ_FALSE
/**
 * Increase the chunk size of the endpoint's pool.  This is used
 * extensively at startup - we see 30-40MB in UTs - and the default
 * chunk size of 4000 bytes is extremely inefficient.  Increase it.
 */
#define PJSIP_POOL_LEN_ENDPT 20000000
#define PJSIP_POOL_INC_ENDPT 10000000
/**
 * Disable retransmission of 1XX responses - this makes sense for UEs,
 * but not for intermediate proxies (who should just forward the
 * retransmissions that UEs generate).
 */
#define PJSIP_TSX_1XX_RETRANS_DELAY 0
/**
 * Move to soft assert behaviour rather than hard asserts.
 */
extern int pj_log_get_level(void);
extern void pj_log_1(const char *src, const char *format, ...);
#define pj_assert(expr) \
          if (!(expr)) { \
              if (pj_log_get_level() >= 1) { \
                  pj_log_1("Assert failed:", "%s:%d %s", \
                           __FILE__, __LINE__, #expr); \
              } \
          }

