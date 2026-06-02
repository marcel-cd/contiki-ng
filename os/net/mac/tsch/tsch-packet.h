/*
 * Copyright (c) 2014, SICS Swedish ICT.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \addtogroup tsch
 * @{
 * \file
 *	TSCH packet parsing and creation. EBs and EACKs.
*/

#ifndef TSCH_PACKET_H_
#define TSCH_PACKET_H_

/********** Includes **********/

#include "contiki.h"
#include "net/mac/framer/frame802154.h"
#include "net/mac/framer/frame802154e-ie.h"

/********** Functions *********/

/**
 * \brief Construct Enhanced ACK packet
 * \param buf The buffer where to build the EACK
 * \param buf_size The buffer size
 * \param dest_addr The link-layer address of the neighbor we are ACKing
 * \param seqno The sequence number we are ACKing
 * \param drift The time offset in usec measured at Rx of the packer we are ACKing
 * \param nack Value of the NACK bit
 * \param secured 1 if the inbound data frame had FCF.security_enabled=1 and
 *                the ACK should mirror that (default TSCH behavior). 0 if the
 *                inbound was unsecured (e.g. a CoJP pledge with no keys yet) —
 *                in which case the ACK must also be unsecured, otherwise the
 *                pledge sees `!failed to authenticate ACK` and the TX is
 *                marked NO_ACK even though the gateway received it.
 * \return The length of the packet that was created. -1 if failure.
 */
int tsch_packet_create_eack(uint8_t *buf, uint16_t buf_size,
                            const linkaddr_t *dest_addr, uint8_t seqno,
                            int16_t drift, int nack, uint8_t secured);
/**
 * \brief Parse enhanced ACK packet
 * \param buf The buffer where to parse the EACK from
 * \param buf_size The buffer size
 * \param seqno The sequence number we are expecting
 * \param frame The frame structure where to store parsed fields
 * \param ies The IE structure where to store parsed IEs
 * \param hdr_len A pointer where to store the length of the parsed header
 * \return 1 if the EACK is correct and acknowledges the specified frame, 0 otherwise
 */
int tsch_packet_parse_eack(const uint8_t *buf, int buf_size,
    uint8_t seqno, frame802154_t *frame, struct ieee802154_ies *ies, uint8_t *hdr_len);
/**
 * \brief Create an EB packet directly in packetbuf
 * \param hdr_len A pointer where to store the length of the created header
 * \param tsch_sync_ie_ptr A pointer where to store the address of the TSCH synchronization IE
 * \return The total length of the EB
 */
int tsch_packet_create_eb(uint8_t *hdr_len, uint8_t *tsch_sync_ie_ptr);
/**
 * \brief Update ASN in EB packet
 * \param buf The buffer that contains the EB
 * \param buf_size The buffer size
 * \param tsch_sync_ie_offset The offset of the TSCH synchronization IE, in which the ASN is to be written
 * \return 1 if success, 0 otherwise
 */
int tsch_packet_update_eb(uint8_t *buf, int buf_size, uint8_t tsch_sync_ie_offset);
/**
 * \brief Parse EB
 * \param buf The buffer where to parse the EB from
 * \param buf_size The buffer sizecting
 * \param frame The frame structure where to store parsed fields
 * \param ies The IE structure where to store parsed IEs
 * \param hdrlen A pointer where to store the length of the parsed header
 * \param frame_without_mic When set, the security MIC will not be parsed
 * \return The length of the parsed EB
  */
int tsch_packet_parse_eb(const uint8_t *buf, int buf_size,
    frame802154_t *frame, struct ieee802154_ies *ies,
    uint8_t *hdrlen, int frame_without_mic);
/**
 * \brief Set frame pending bit in a packet (whose header was already build)
 * \param buf The buffer where the packet resides
 * \param buf_size The buffer size
 */
void tsch_packet_set_frame_pending(uint8_t *buf, int buf_size);
/**
 * \brief Get frame pending bit from a packet
 * \param buf The buffer where the packet resides
 * \param buf_size The buffer size
 * \return The value of the frame pending bit, 1 or 0
 */
int tsch_packet_get_frame_pending(uint8_t *buf, int buf_size);
/**
 * \brief Set a packet attribute for the current eack. We not use standard
 * packetbuf for eacks because these are generated from interrupt context.
 * \param type The attribute identifier
 * \param val The attribute value
 */
void tsch_packet_eackbuf_set_attr(uint8_t type, const packetbuf_attr_t val);
/**
 * \brief Return the value of a specified attribute
 * \param type The attribute identifier
 * \return The attribute value
 */
packetbuf_attr_t tsch_packet_eackbuf_attr(uint8_t type);

/* ---- Klikk wall-clock-over-EB extension (see docs/leaf-time-sync.md) ---- */

/**
 * \brief EB UTC provider (coordinator side).
 *
 * Registered by the gateway's mesh_time module. Called from
 * tsch_packet_update_eb() at EB TX time (slot-operation context — must be
 * cheap and non-blocking). Must return the UTC, in microseconds since the
 * Unix epoch, corresponding to the CURRENT tsch_current_asn.
 *
 * \param out_utc_us Where to write the UTC (us). Written only on success.
 * \return 1 if a valid wall-clock was available and *out_utc_us was written,
 *         0 otherwise (the EB then advertises "no time").
 */
typedef int (*tsch_eb_utc_provider_t)(int64_t *out_utc_us);
void tsch_eb_utc_provider_set(tsch_eb_utc_provider_t provider);

/**
 * \brief EB UTC sink (leaf side).
 *
 * Registered by the leaf application. Invoked from tsch_packet_parse_eb()
 * whenever an EB carrying a valid Klikk UTC IE is parsed, with the EB's
 * reference ASN and its UTC (us). The leaf derives wall-clock from its own
 * tsch_current_asn:
 *   utc_now = utc_us + TSCH_ASN_DIFF(tsch_current_asn, ref_asn) * timeslot_us
 * Runs in TSCH context — keep it short (store the anchor and return).
 */
typedef void (*tsch_eb_utc_sink_t)(struct tsch_asn_t ref_asn, int64_t utc_us);
void tsch_eb_utc_sink_set(tsch_eb_utc_sink_t sink);

#endif /* TSCH_PACKET_H_ */
/** @} */
