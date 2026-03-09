#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>

extern "C"
{
#include "picoquic.h"
#include "picosocks.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"
}

#define TEST_ALPN "koh_test"
#define TEST_PORT 4433

int server_callback(picoquic_cnx_t *cnx,
                    uint64_t stream_id, uint8_t *bytes, size_t length,
                    picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *stream_ctx)
{

    switch (fin_or_event)
    {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (length > 0)
        {
            struct sockaddr *peer_addr;
            picoquic_get_peer_addr(cnx, &peer_addr);
            uint16_t port = (peer_addr->sa_family == AF_INET) ? ntohs(((struct sockaddr_in *)peer_addr)->sin_port) : ntohs(((struct sockaddr_in6 *)peer_addr)->sin6_port);

            printf("Server: Received %zu bytes from PORT %u: %.*s\n",
                   length, port, (int)length, (char *)bytes);
            picoquic_add_to_stream(cnx, stream_id, bytes, length, (fin_or_event == picoquic_callback_stream_fin));
        }
        break;
    case picoquic_callback_path_available:
        printf("Server: New Path AVAILABLE! Path ID: %llu\n", (unsigned long long)stream_id);
        break;
    case picoquic_callback_path_suspended:
        printf("Server: Path SUSPENDED! Path ID: %llu\n", (unsigned long long)stream_id);
        break;
    case picoquic_callback_path_deleted:
        printf("Server: Path DELETED! Path ID: %llu\n", (unsigned long long)stream_id);
        break;
    case picoquic_callback_ready:
        printf("Server: Handshake Ready.\n");
        break;
    default:
        break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    picoquic_quic_t *quic = picoquic_create(8, "../../certs/cert.pem", "../../certs/key.pem", NULL, TEST_ALPN,
                                            server_callback, NULL, NULL, NULL, NULL, picoquic_current_time(), NULL, NULL, NULL, 0);

    printf("hellp\n");
    if (quic == NULL)
        return -1;
    /* Safe MP SETTINGS via API */
    picoquic_set_default_multipath_option(quic, 1);
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_path_id, 4);
    picoquic_set_default_tp_value(quic, picoquic_tp_active_connection_id_limit, 8);
    picoquic_enable_path_callbacks_default(quic, 1);

    printf("Starting MPQUIC Server on port %d...\n", TEST_PORT);
    picoquic_packet_loop(quic, TEST_PORT, 0, 0, 0, 0, NULL, NULL);

    picoquic_free(quic);
    return 0;
}
