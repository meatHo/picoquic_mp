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

// 두번째 포트 alt_port로 서버에 연결하는 함수
// 지금은 로컬호스트로 고정되어서 이거를 다른 IP로 바꾸면 됨. 여러 NIC사용하게 되는 것
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

    // alt_addr로 PATH_CHALLENGE 패킷 보내 패쓰 살아있는제 검사
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
            // 새 데이터를 보낼 스트림 번호 할당받음
            uint64_t mp_stream_id = picoquic_get_next_local_stream_id(cnx, 0);
            /* Stream must be marked active before we can set its path affinity */
            // 라이브러리 내부 스트림 관리 테이블에 이 스트림 번호 등록
            picoquic_mark_active_stream(cnx, mp_stream_id, 1, NULL);

            /* We use the stream_id passed in the callback which is the unique path ID */
            // 특정 스트림을 특정 경로에 고정
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
    // quic context 생성 - 연결 정보 관리하는 객체
    picoquic_quic_t *quic = picoquic_create(1, NULL, NULL, NULL, TEST_ALPN, NULL, NULL, NULL, NULL, NULL, picoquic_current_time(), NULL, NULL, NULL, 0);

    // 멀티패스 옵션 활성화
    picoquic_set_default_multipath_option(quic, 1);

    // Transport Parameter 설정 - 초기 최대 4개의 추가 경로 처리할 수 있다
    picoquic_set_default_tp_value(quic, picoquic_tp_initial_max_path_id, 4);
    picoquic_set_default_tp_value(quic, picoquic_tp_active_connection_id_limit, 8);

    // 경로가 새로 생기거나 없어질 때 callback 주도록 설정
    picoquic_enable_path_callbacks_default(quic, 1);

    client_ctx_t ctx = {0};
    int is_ipv6 = 0;
    if (picoquic_get_server_address(server_name, TEST_PORT, &ctx.server_address, &is_ipv6) != 0)
    {
        fprintf(stderr, "Cannot resolve server address: %s\n", server_name);
        return -1;
    }
    printf("Resolved %s to %s\n", server_name, (is_ipv6) ? "IPv6" : "IPv4");

    /*
     * 역할: 서버와의 논리적인 연결(Connection)을 생성합니다.
     * picoquic_null_connection_id: 초기 연결 ID는 라이브러리가 자동으로 생성하도록 맡깁니다.
     * TEST_SNI / TEST_ALPN: TLS 보안 연결을 위한 정보(서버 이름 확인 및 프로토콜 이름)를 전달합니다.
     * 1: 이 연결의 주체가 클라이언트(Client Mode)임을 명시합니다.
     */
    ctx.cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *)&ctx.server_address, picoquic_current_time(), 0, TEST_SNI, TEST_ALPN, 1);
    picoquic_set_callback(ctx.cnx, client_callback, &ctx);

    //* 역할: 서버에게 첫 번째 패킷(Client Hello)을 보내서 연결을 시작(Handshake)하라고 명령
    picoquic_start_client_cnx(ctx.cnx);
    ctx.main_stream_id = picoquic_get_next_local_stream_id(ctx.cnx, 0);
    picoquic_mark_active_stream(ctx.cnx, ctx.main_stream_id, 1, NULL);
    picoquic_packet_loop_param_t param = {0};
    param.local_af = ctx.server_address.ss_family;
    param.extra_socket_required = 1;

    // OS로부터 통신용 포트를 하나 더 할당받아 멀티패스용 소켓을 준비하라는 뜻
    picoquic_packet_loop_v2(quic, &param, client_loop_cb, &ctx);
    picoquic_free(quic);
    return 0;
}

/*
  수정 시나리오 (예시)
   * NIC 1 (메인): 192.168.1.10 (이더넷)
   * NIC 2 (멀티패스): 192.168.1.20 (Wi-Fi)


  수정될 코드의 모습 (개념적 코드)


    1 void probe_alt_path(picoquic_cnx_t *cnx, client_ctx_t *ctx)
    2 {
    3     struct sockaddr_storage alt_addr;
    4     memset(&alt_addr, 0, sizeof(alt_addr));
    5
    6     if (ctx->server_address.ss_family == AF_INET)
    7     {
    8         struct sockaddr_in *sin = (struct sockaddr_in *)&alt_addr;
    9         sin->sin_family = AF_INET;
   10
   11         // [수정 포인트] 127.0.0.1 대신 2번 NIC의 실제 IP를 넣습니다.
   12         sin->sin_addr.s_addr = inet_addr("192.168.1.20");
   13
   14         // 할당받은 포트 번호 설정
   15         sin->sin_port = htons(ctx->alt_port);
   16     }
   17
   18     printf("Client: Probing path from NIC 2 (192.168.1.20) to Server...\n");
   19
   20     // 이 함수가 호출될 때, 라이브러리는 192.168.1.20 IP를 가진
   21     // 두 번째 네트워크 카드를 통해 서버로 데이터를 보냅니다.
   22     picoquic_probe_new_path(cnx,
   23                             (struct sockaddr *)&ctx->server_address,
   24                             (struct sockaddr *)&alt_addr,
   25                             picoquic_current_time());
   26 }

  ---

  왜 이렇게 하면 작동하나요?


   1. 소스 IP 바인딩: picoquic_probe_new_path 함수의 세 번째 인자인 alt_addr에 특정 NIC의 IP를 넣으면, OS는 해당 IP를 가진
      네트워크 인터페이스를 강제로 사용하여 패킷을 내보내게 됩니다.
   2. 4-Tuple의 변화: QUIC 서버는 (Src IP, Src Port, Dest IP, Dest Port) 이 4가지 정보 중 하나만 달라도 새로운 경로(Path)로
      인식합니다.
       * 경로 0: (IP 1, Port 1, Server IP, Server Port)
       * 경로 1: (IP 2, Port 2, Server IP, Server Port)
   3. 병렬 전송: 이렇게 두 경로가 서버에서 승인(Validation)되면, 데이터는 NIC 1과 NIC 2를 통해 동시에 분산되어 전송됩니다.


  요약
  지금 포트만 바꿔서 성공하셨던 방식에서 alt_addr에 들어가는 IP 주소만 두 번째 NIC의 실제 IP로 바꿔주면, 바로 실제 망 분리
  환경에서의 멀티패스 테스트가 가능해집니다. 나중에 실제 물리적인 NIC 두 개가 준비되었을 때 이 부분만 수정하시면 됩니다!
*/