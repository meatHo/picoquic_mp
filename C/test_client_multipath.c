#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picosocks.h"
#include "picoquic_utils.h"
#include "picoquic_packet_loop.h"

#define TEST_ALPN "koh_test"
#define TEST_PORT 4433
#define TEST_SNI "test.example.com"

typedef struct st_client_ctx_t
{
    int is_disconnected;
    int data_received;
    picoquic_cnx_t *cnx;
    struct sockaddr_storage server_address;
    uint16_t alt_port;
    int alt_path_probed;
    uint64_t main_stream_id;
} client_ctx_t;

int is_mp_enabled(picoquic_cnx_t *cnx)
{
    picoquic_tp_t const *lt = picoquic_get_transport_parameters(cnx, 1);
    picoquic_tp_t const *rt = picoquic_get_transport_parameters(cnx, 0);
    return (lt && rt && lt->initial_max_path_id > 0 && rt->initial_max_path_id > 0);
}

void probe_alt_path(picoquic_cnx_t *cnx, client_ctx_t *ctx)
{
    if (ctx->alt_port == 0 || ctx->cnx == NULL || ctx->alt_path_probed)
        return;
    struct sockaddr_storage alt_addr;
    memset(&alt_addr, 0, sizeof(alt_addr));
    if (ctx->server_address.ss_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&alt_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(0x7F000001); // 127.0.0.1
        sin->sin_port = htons(ctx->alt_port);
    }
    else
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&alt_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6addr_loopback;
        sin6->sin6_port = htons(ctx->alt_port);
    }
    printf("Client: Probing path from PORT %u to SERVER %u...\n", ctx->alt_port, TEST_PORT);
    int ret = picoquic_probe_new_path(cnx, (struct sockaddr *)&ctx->server_address, (struct sockaddr *)&alt_addr, picoquic_current_time());
    if (ret != 0)
    {
        printf("Client: picoquic_probe_new_path failed with error %d\n", ret);
    }
    ctx->alt_path_probed = 1;
}

int client_callback(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes, size_t length,
                    picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *stream_ctx)
{
    client_ctx_t *ctx = (client_ctx_t *)callback_ctx;
    if (!ctx)
        return 0;
    switch (fin_or_event)
    {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (length > 0)
        {
            printf("Client: Received echo: %.*s\n", (int)length, (char *)bytes);
            ctx->data_received++;
            if (ctx->data_received >= 2)
            {
                printf("Client: Success! Closing.\n");
                picoquic_close(cnx, 0);
            }
        }
        break;
    case picoquic_callback_ready:
        printf("Client: Ready. MP: %s\n", is_mp_enabled(cnx) ? "YES" : "NO");
        picoquic_add_to_stream(cnx, stream_id, (uint8_t *)"PrimaryData", 11, 0);
        if (ctx->alt_port != 0)
        {
            probe_alt_path(cnx, ctx);
        }
        else
        {
            printf("Client: Alt port not ready yet.\n");
        }
        break;
    case picoquic_callback_path_available:
        printf("Client: PATH AVAILABLE! Path ID: %llu\n", (unsigned long long)stream_id);
        {
            uint64_t mp_stream_id = picoquic_get_next_local_stream_id(cnx, 0);
            /* Stream must be marked active before we can set its path affinity */
            picoquic_mark_active_stream(cnx, mp_stream_id, 1, NULL);

            /* We use the stream_id passed in the callback which is the unique path ID */
            if (picoquic_set_stream_path_affinity(cnx, mp_stream_id, stream_id) == 0)
            {
                printf("Client: Sending MP Data on stream %llu (Path %llu)\n", (unsigned long long)mp_stream_id, (unsigned long long)stream_id);
                picoquic_add_to_stream(cnx, mp_stream_id, (uint8_t *)"MultipathData", 13, 1);
            }
            else
            {
                printf("Client: Failed to set path affinity for stream %llu\n", (unsigned long long)mp_stream_id);
            }
        }
        break;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
        ctx->is_disconnected = 1;
        break;
    default:
        break;
    }
    return 0;
}

static int client_loop_cb(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum cb_mode, void *callback_ctx, void *callback_arg)
{
    client_ctx_t *ctx = (client_ctx_t *)callback_ctx;
    if (!ctx)
        return 0;
    switch (cb_mode)
    {
    case picoquic_packet_loop_ready:
        if (callback_arg)
            ((picoquic_packet_loop_options_t *)callback_arg)->provide_alt_port = 1;
        break;
    case picoquic_packet_loop_alt_port:
        if (callback_arg)
        {
            ctx->alt_port = *(uint16_t *)callback_arg;
            printf("Client: Alt port %u ready.\n", ctx->alt_port);
            if (ctx->cnx && picoquic_get_cnx_state(ctx->cnx) >= picoquic_state_ready)
                probe_alt_path(ctx->cnx, ctx);
        }
        break;
    case picoquic_packet_loop_after_send:
        if (ctx->is_disconnected)
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        break;
    default:
        break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char const *server_name = (argc > 1) ? argv[1] : "127.0.0.1";
    picoquic_quic_t *quic = picoquic_create(1, NULL, NULL, NULL, TEST_ALPN, NULL, NULL, NULL, NULL, NULL, picoquic_current_time(), NULL, NULL, NULL, 0);
    picoquic_set_default_multipath_option(quic, 1);
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_path_id, 4);
    picoquic_set_default_tp_value(quic, picoquic_tp_active_connection_id_limit, 8);
    picoquic_enable_path_callbacks_default(quic, 1);
    client_ctx_t ctx = {0};
    int is_ipv6 = 0;
    if (picoquic_get_server_address(server_name, TEST_PORT, &ctx.server_address, &is_ipv6) != 0)
    {
        fprintf(stderr, "Cannot resolve server address: %s\n", server_name);
        return -1;
    }
    printf("Resolved %s to %s\n", server_name, (is_ipv6) ? "IPv6" : "IPv4");

    ctx.cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *)&ctx.server_address, picoquic_current_time(), 0, TEST_SNI, TEST_ALPN, 1);
    picoquic_set_callback(ctx.cnx, client_callback, &ctx);

    picoquic_start_client_cnx(ctx.cnx);
    ctx.main_stream_id = picoquic_get_next_local_stream_id(ctx.cnx, 0);
    picoquic_mark_active_stream(ctx.cnx, ctx.main_stream_id, 1, NULL);
    picoquic_packet_loop_param_t param = {0};
    param.local_af = ctx.server_address.ss_family;
    param.extra_socket_required = 1;
    picoquic_packet_loop_v2(quic, &param, client_loop_cb, &ctx);
    picoquic_free(quic);
    return 0;
}
