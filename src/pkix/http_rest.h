/* Загрузка издателя и CRL по HTTP в этот инструмент не входит. */
#ifndef HTTP_REST_H
#define HTTP_REST_H
#include <glib.h>
typedef struct _HttpPeer HttpPeer;
typedef struct {
    char *content;
    int length;
    GData *headers;
} REST_Message;
HttpPeer *http_peer_new(char *location, int len, char **url);
GError *http_peer_request(HttpPeer *peer, const char *method, char *url,
                          REST_Message *req, REST_Message *resp);
void http_peer_free(HttpPeer *peer);
#endif
