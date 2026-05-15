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
 * \file
 *         TSCH security
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 */

/**
 * \addtogroup tsch
 * @{
*/

#include "contiki.h"
#include "net/mac/tsch/tsch.h"
#include "net/mac/framer/frame802154.h"
#include "net/mac/framer/framer-802154.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "lib/ccm-star.h"
#include "lib/aes-128.h"
#include <stdio.h>
#include <string.h>

#if LLSEC802154_ENABLED && !LLSEC802154_USES_EXPLICIT_KEYS
#error LLSEC802154_ENABLED set but LLSEC802154_USES_EXPLICIT_KEYS unset
#endif /* LLSEC802154_ENABLED */

/* The two keys K1 and K2 from 6TiSCH minimal configuration
 * K1: well-known, used for EBs
 * K2: secret, used for data and ACK
 *
 * No longer `const` — runtime callers (gateway-efr fleet_config,
 * klikk-zephyr provisioning blob commit) overwrite slot K2 with the
 * per-tenant fleet key once the cloud has issued one. K1 stays as
 * compiled (the IETF 6TiSCH-minimal well-known constant; baking it
 * in is the standard pattern). See tsch_security_set_key() below.
 */
static aes_key keys[] = {
  TSCH_SECURITY_K1,
  TSCH_SECURITY_K2
};
#define N_KEYS (sizeof(keys) / sizeof(aes_key))

/*---------------------------------------------------------------------------*/
int
tsch_security_set_key(uint8_t key_index, const uint8_t key[16])
{
  if(key == NULL) {
    return -1;
  }
  /* IEEE key_index is 1-based and 0 means "unsecured"; map to the
   * 0-based array slot. */
  if(key_index < 1 || key_index > N_KEYS) {
    return -1;
  }
  memcpy(keys[key_index - 1], key, sizeof(aes_key));
  return 0;
}

/*---------------------------------------------------------------------------*/
static void
tsch_security_init_nonce(uint8_t *nonce,
                         const linkaddr_t *sender, struct tsch_asn_t *asn)
{
  memcpy(nonce, sender, 8);
  nonce[8] = asn->ms1b;
  nonce[9] = (asn->ls4b >> 24) & 0xff;
  nonce[10] = (asn->ls4b >> 16) & 0xff;
  nonce[11] = (asn->ls4b >> 8) & 0xff;
  nonce[12] = (asn->ls4b) & 0xff;
}
/*---------------------------------------------------------------------------*/
/* CoJP pledge-mode flags — see tsch-security.h for the public setters
 * tsch_security_force_next_unsecured() and tsch_security_set_pledge_mode().
 * Forward-declared here so tsch_security_check_level() and
 * tsch_security_parse_frame() (defined further down) can read them; the
 * setters themselves live near the end of the file with the rest of the
 * CoJP pledge support helpers. */
static volatile bool s_force_next_unsecured;
static volatile bool s_pledge_mode;
/*---------------------------------------------------------------------------*/
static int
tsch_security_check_level(const frame802154_t *frame)
{
  uint8_t required_security_level;
  uint8_t required_key_index;

  /* Sanity check */
  if(frame == NULL) {
    return 0;
  }

  /* Non-secured frame, ok iff we are not in a secured PAN
   * (i.e. scanning or associated to a non-secured PAN). */
  if(frame->fcf.security_enabled == 0) {
    if(tsch_is_associated == 1 && tsch_is_pan_secured == 1) {
      /* 6TiSCH Constrained Join Protocol (RFC 9031): factory-fresh
       * pledges send their Join Request with security_enabled=0
       * because they don't yet have a K2. The Join Proxy (the
       * gateway here, or a joined leaf acting as JP-N for distant
       * pledges) must accept unsecured DATA unicasts so the
       * application-layer cojp_relay can shuttle the OSCORE payload
       * to the JRC.
       *
       * Trust gate stays at OSCORE: the inner payload is
       * end-to-end-protected under PSK_JRC, so accepting unsecured
       * here doesn't extend trust to the sender — it just lets the
       * application decide. The RAIL HW filter has already validated
       * that the destination matches our PAN + linkaddr by the time
       * the frame reaches this check, so we don't need to re-check
       * addressing here.
       *
       * Accept both DATA and ACK frames unsecured: pledges send the
       * Join Request as DATA (FRAME802154_DATAFRAME) and reply to our
       * unsecured downlink with an unsecured Enh-ACK (FRAME802154_ACKFRAME)
       * per 802.15.4-2015 — mirroring the data frame's security level.
       * Without the ACK case the gateway logs "!failed to authenticate
       * ACK" on every downlink to a pledge and marks its own TX as
       * NO_ACK even though the pledge accepted the frame and replied.
       * Beacons (EBs) and MAC command frames stay rejected unsecured. */
      return frame->fcf.frame_type == FRAME802154_DATAFRAME ||
             frame->fcf.frame_type == FRAME802154_ACKFRAME;
    }
    return 1;
  }

  /* The frame is secured, that we are not in an unsecured PAN */
  if(tsch_is_associated == 1 && tsch_is_pan_secured == 0) {
    return 0;
  }

  /* The frame is secured, check its security level */
  switch(frame->fcf.frame_type) {
    case FRAME802154_BEACONFRAME:
      required_security_level = TSCH_SECURITY_KEY_SEC_LEVEL_EB;
      required_key_index = TSCH_SECURITY_KEY_INDEX_EB;
      break;
    case FRAME802154_ACKFRAME:
      required_security_level = TSCH_SECURITY_KEY_SEC_LEVEL_ACK;
      required_key_index = TSCH_SECURITY_KEY_INDEX_ACK;
      break;
    default:
      required_security_level = TSCH_SECURITY_KEY_SEC_LEVEL_OTHER;
      required_key_index = TSCH_SECURITY_KEY_INDEX_OTHER;
      break;
  }
  return ((frame->aux_hdr.security_control.security_level ==
           required_security_level) &&
          frame->aux_hdr.key_index == required_key_index);
}
/*---------------------------------------------------------------------------*/
unsigned int
tsch_security_mic_len(const frame802154_t *frame)
{
  if(frame != NULL && frame->fcf.security_enabled) {
    return 2 << (frame->aux_hdr.security_control.security_level & 0x03);
  } else {
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
unsigned int
tsch_security_secure_frame(uint8_t *hdr, uint8_t *outbuf,
                           int hdrlen, int datalen, struct tsch_asn_t *asn)
{
  frame802154_t frame;
  uint8_t key_index = 0;
  uint8_t security_level = 0;
  uint8_t with_encryption;
  uint8_t mic_len;
  uint8_t nonce[16];
  struct ieee802154_ies ies;

  uint8_t a_len;
  uint8_t m_len;

  if(hdr == NULL || outbuf == NULL || hdrlen < 0 || datalen < 0) {
    return 0;
  }

  /* Parse the frame header to extract security settings */
  if(frame802154_parse(hdr, hdrlen + datalen, &frame) < 3) {
    return 0;
  }

  memset(&ies, 0, sizeof(ies));
  if(frame802154e_parse_information_elements(hdr + hdrlen, datalen, &ies) > 0) {
    /* put Header IEs into the header part which is not encrypted */
    hdrlen += ies.ie_payload_ie_offset;
    datalen -= ies.ie_payload_ie_offset;
  }

  if(!frame.fcf.security_enabled) {
    /* Security is not enabled for this frame, we're done */
    return 0;
  }

  /* Read security key index */
  key_index = frame.aux_hdr.key_index;
  security_level = frame.aux_hdr.security_control.security_level;
  with_encryption = (security_level & 0x4) ? 1 : 0;
  mic_len = tsch_security_mic_len(&frame);

  if(key_index == 0 || key_index > N_KEYS) {
    return 0;
  }

  tsch_security_init_nonce(nonce, &linkaddr_node_addr, asn);

  if(with_encryption) {
    a_len = hdrlen;
    m_len = datalen;
  } else {
    a_len = hdrlen + datalen;
    m_len = 0;
  }

  /* Copy source data to output */
  if(hdr != outbuf) {
    memcpy(outbuf, hdr, a_len + m_len);
  }

  CCM_STAR.set_key(keys[key_index - 1]);

  CCM_STAR.aead(nonce,
                outbuf + a_len, m_len,
                outbuf, a_len,
                outbuf + hdrlen + datalen, mic_len, 1);

  return mic_len;
}
/*---------------------------------------------------------------------------*/
unsigned int
tsch_security_parse_frame(const uint8_t *hdr, int hdrlen, int datalen,
                          const frame802154_t *frame, const linkaddr_t *sender,
                          struct tsch_asn_t *asn)
{
  uint8_t generated_mic[16];
  uint8_t key_index = 0;
  uint8_t security_level = 0;
  uint8_t with_encryption;
  uint8_t mic_len;
  uint8_t nonce[16];
  uint8_t a_len;
  uint8_t m_len;
  struct ieee802154_ies ies;

  if(frame == NULL || hdr == NULL || hdrlen < 0 || datalen < 0) {
    return 0;
  }

  if(!tsch_security_check_level(frame)) {
    /* Wrong security level */
    return 0;
  }

  /* No security: nothing more to check */
  if(!frame->fcf.security_enabled) {
    return 1;
  }

  /* CoJP pledge: accept EBs without MIC verification. The pledge only
   * has the compiled-in placeholder K1 — the gateway signs its EBs with
   * the per-tenant K1, so MIC verify would always fail. The EB body
   * (sec-level=1 = MIC-32 only, no encryption) is readable plaintext;
   * pledge syncs on the timing/slotframe info and lets OSCORE filter
   * out malicious EBs at the Join_Request/Response step. */
  if(s_pledge_mode && frame->fcf.frame_type == FRAME802154_BEACONFRAME) {
    return 1;
  }

  key_index = frame->aux_hdr.key_index;
  security_level = frame->aux_hdr.security_control.security_level;
  with_encryption = (security_level & 0x4) ? 1 : 0;
  mic_len = tsch_security_mic_len(frame);

  /* Check if key_index is in supported range */
  if(key_index == 0 || key_index > N_KEYS) {
    return 0;
  }

  memset(&ies, 0, sizeof(ies));
  (void)frame802154e_parse_information_elements(hdr + hdrlen, datalen, &ies);
  /* put Header IEs into the header part which is not encrypted */
  hdrlen += ies.ie_payload_ie_offset;
  datalen -= ies.ie_payload_ie_offset;

  tsch_security_init_nonce(nonce, sender, asn);

  if(with_encryption) {
    a_len = hdrlen;
    m_len = datalen;
  } else {
    a_len = hdrlen + datalen;
    m_len = 0;
  }

  CCM_STAR.set_key(keys[key_index - 1]);

  CCM_STAR.aead(nonce,
                (uint8_t *)hdr + a_len, m_len,
                (uint8_t *)hdr, a_len,
                generated_mic, mic_len, 0);

  if(mic_len > 0 && memcmp(generated_mic, hdr + hdrlen + datalen, mic_len) != 0) {
    return 0;
  } else {
    return 1;
  }
}
/*---------------------------------------------------------------------------*/
/* CoJP pledge / JP support — see tsch_security_force_next_unsecured() in
 * tsch-security.h. Sticky flag, cleared by the caller after the higher-
 * layer send returns. (Storage declared at the top of the file so the
 * receive-path code can read it without a forward-reference issue.) */
void
tsch_security_force_next_unsecured(bool on)
{
  s_force_next_unsecured = on;
}

/* CoJP pledge — when set, EB MIC verification is bypassed. A pledge has no
 * fleet K1 yet (only the compiled-in placeholder), so MIC-checking gateway
 * EBs that are signed under the per-tenant K1 always fails. Per RFC 9031 /
 * the Klikk CoJP architecture doc, the pledge syncs on the EB body
 * (plaintext, EB sec-level=1 = MIC-32 only) and trusts the OSCORE layer
 * to filter out malicious EBs at the Join_Request/Response step. Cleared
 * by the caller once the leaf installs fleet K1+K2 from the provisioning
 * blob. */
void
tsch_security_set_pledge_mode(bool on)
{
  s_pledge_mode = on;
}
/*---------------------------------------------------------------------------*/
void
tsch_security_set_packetbuf_attr(uint8_t frame_type)
{
#if LLSEC802154_ENABLED
  if(tsch_is_pan_secured) {
    /* Set security level, key id and index */
    switch(frame_type) {
      case FRAME802154_ACKFRAME:
        /* For ACKs, we set attriburtes via tsch_packet_eackbuf_set_attr, as classic
         * interrupts can not be used from interrupt context. */
        tsch_packet_eackbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, TSCH_SECURITY_KEY_SEC_LEVEL_ACK);
        tsch_packet_eackbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_1_BYTE_KEY_ID_MODE);
        tsch_packet_eackbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, TSCH_SECURITY_KEY_INDEX_ACK);
        break;
      case FRAME802154_BEACONFRAME:
        packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, TSCH_SECURITY_KEY_SEC_LEVEL_EB);
        packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_1_BYTE_KEY_ID_MODE);
        packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, TSCH_SECURITY_KEY_INDEX_EB);
        break;
      default:
        if(s_force_next_unsecured) {
          /* CoJP override — leave FCF.security_enabled = 0 on the wire.
           * packetbuf_clear() (in sicslowpan_output / NETSTACK_MAC.send
           * path) zeroed PACKETBUF_ATTR_SECURITY_LEVEL already; setting
           * it again to 0 is defensive. */
          packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, 0);
          packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, 0);
          packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, 0);
          break;
        }
        packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, TSCH_SECURITY_KEY_SEC_LEVEL_OTHER);
        packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_1_BYTE_KEY_ID_MODE);
        packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, TSCH_SECURITY_KEY_INDEX_OTHER);
        break;
    }
  }
#endif /* LLSEC802154_ENABLED */
}
/** @} */
