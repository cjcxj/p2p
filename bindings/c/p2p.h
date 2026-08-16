#ifndef P2P_C_H
#define P2P_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct p2p_session p2p_session;

typedef void (*p2p_event_cb)(int event, const char *peer_id,
                             const uint8_t *data, size_t len, void *userdata);

/* Event constants mirror sdk/event.go */
enum {
  P2P_EVENT_STATE_CHANGED = 1,
  P2P_EVENT_PEER_JOINED = 2,
  P2P_EVENT_PEER_LEFT = 3,
  P2P_EVENT_PEER_CONNECTED = 4,
  P2P_EVENT_DATA = 5,
  P2P_EVENT_ERROR = 6,
  P2P_EVENT_DEBUG = 7,
  P2P_EVENT_PATH_CHANGED = 8
};

p2p_session *p2p_session_new(const char *server, const char *stun,
                             const char *token, int enable_tls,
                             const char *tls_server_name,
                             int tls_insecure_skip_verify,
                             p2p_event_cb cb, void *userdata);

int p2p_session_connect(p2p_session *s, const char *room);
int p2p_session_send(p2p_session *s, const char *peer, const uint8_t *data,
                     size_t len);
int p2p_session_broadcast(p2p_session *s, const uint8_t *data, size_t len);
const char *p2p_session_local_ip(p2p_session *s);
const char *p2p_session_subnet(p2p_session *s);
void p2p_session_free(p2p_session *s);

#ifdef __cplusplus
}
#endif

#endif /* P2P_C_H */
