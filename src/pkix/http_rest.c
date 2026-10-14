#include "http_rest.h"
HttpPeer *http_peer_new(char *location, int len, char **url)
{
    (void)location; (void)len; (void)url;
    return NULL;
}
GError *http_peer_request(HttpPeer *peer, const char *method, char *url,
                          REST_Message *req, REST_Message *resp)
{
    (void)peer; (void)method; (void)url; (void)req; (void)resp;
    return NULL;
}
void http_peer_free(HttpPeer *peer)
{
    (void)peer;
}
