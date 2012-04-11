
#include "uv.h"
#include "task.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <io.h>

typedef struct poll_connection_s {
  uv_poll_t w;
  SOCKET sock;
} poll_connection_t;


static void poll_cb(uv_poll_t* handle, int status, int events) {
  char buf[1024];
  int result;
  poll_connection_t* p = CONTAINING_RECORD(handle, poll_connection_t, w);

  ASSERT(status == 0);
  
  if (events & UV_READABLE) {
    result = recv(p->sock, buf, sizeof buf, 0);
    ASSERT(result > 0);
    write(1, buf, result);
} else {
    printf("\nNot readable!\n");
  }

  result = uv_poll_start(handle, UV_READABLE, poll_cb);
  ASSERT(result == 0);
}

void uv_fatal_error(DWORD errno, char* syscall);

void start() {
  poll_connection_t* p = (poll_connection_t*) malloc(sizeof *p);
  uv_poll_t* w = &p->w;
  DWORD result, yes = 1;
  const struct sockaddr_in localhost = uv_ip4_addr("127.0.0.1", 8000);

  p->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  assert(p->sock != INVALID_SOCKET);

  result = connect(p->sock, (const struct sockaddr*) &localhost, sizeof localhost);
  assert(result == 0 || WSAGetLastError() == WSAEWOULDBLOCK);

  result = uv_poll_init_socket(uv_default_loop(), w, p->sock);
  assert(result == 0);

  result = ioctlsocket(p->sock, FIONBIO, &yes);
  assert(result == 0);

  result = uv_poll_start(w, UV_READABLE | UV_WRITABLE, poll_cb);
  assert(result == 0);
}

TEST_IMPL(test2) {
  int i;

  uv_default_loop(); // Initializes winsock on windows systems.

  for (i = 0; i < 100; i++)
    start();

  uv_run(uv_default_loop());
  return 0;
}