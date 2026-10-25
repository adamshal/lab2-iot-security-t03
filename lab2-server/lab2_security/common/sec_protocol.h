#ifndef SEC_PROTOCOL_H
#define SEC_PROTOCOL_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "sec_crypto.h"
#define PROTO_HEADER 44
#define PROTO_PAYLOAD 128
#define PROTO_PACKET (PROTO_HEADER + PROTO_PAYLOAD + SEC_SIG_LEN)
#define PROTO_TIMEOUT 60000
#define PROTO_RETRY 8000
/* Wire types are shared by the two independently built endpoints. */
enum proto_type { HELLO=1, HELLO_ACK, CONFIRM, READY, DATA, DATA_ACK };
enum proto_state { WAIT_HELLO, WAIT_HELLO_ACK, WAIT_CONFIRM, WAIT_READY, WAIT_DATA, PAIRED };
struct protocol {
 bool client, acked, tx_pending;
 enum proto_state state;
 uint8_t own_pub[32], own_priv[32], peer_pub[32];
 uint8_t client_nonce[16], server_nonce[16], dh_pub[32], peer_dh[32], dh_priv[32];
 uint8_t key[16], iv_prefix[7];
 uint8_t tx[PROTO_PACKET]; size_t tx_len;
 uint32_t seq, highest, copies;
 int64_t progress, due;
 char received[PROTO_PAYLOAD+1]; size_t received_len;
};
void proto_init(struct protocol *p, bool client, const uint8_t pub[32],
                const uint8_t priv[32], const uint8_t peer[32], int64_t now);
/* Returns 1 for a NEW authenticated plaintext, 0 for control/duplicate,
 * negative for malformed/unauthenticated/stale packets. */
int proto_receive(struct protocol *p, const uint8_t *wire, size_t len, int64_t now);
/* A nonzero length requests transmission of p->tx. Retries reuse exact bytes. */
size_t proto_poll(struct protocol *p, int64_t now);
bool proto_selftest(void);
#endif
