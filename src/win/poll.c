/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */


#include <assert.h>
#include <io.h>

#include "uv.h"
#include "../uv-common.h"
#include "internal.h"


static const GUID uv_msafd_provider_ids[UV_MSAFD_PROVIDER_COUNT] = {
  {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
  {0xf9eab0c0, 0x26d4, 0x11d0, {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}},
  {0x9fc48064, 0x7298, 0x43e4, {0xb7, 0xbd, 0x18, 0x1f, 0x20, 0x89, 0x79, 0x2a}}
};

typedef struct uv_single_fd_set_s {
  unsigned int fd_count;
  SOCKET fd_array[1];
} uv_single_fd_set_t;


int uv_poll_init(uv_loop_t* loop, uv_poll_t* handle, int fd) {
  return uv_poll_init_socket(loop, handle, (SOCKET) _get_osfhandle(fd));
}


static SOCKET uv__fast_poll_create_peer_socket(HANDLE iocp, WSAPROTOCOL_INFOW* protocol_info) {
  SOCKET sock = 0;

  sock = WSASocketW(protocol_info->iAddressFamily,
                    protocol_info->iSocketType,
                    protocol_info->iProtocol,
                    protocol_info,
                    0,
                    WSA_FLAG_OVERLAPPED);
  if (sock == INVALID_SOCKET) {
    return INVALID_SOCKET;
  }

  if (!SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0)) {
    goto error;
  };

  if (CreateIoCompletionPort((HANDLE) sock,
                              iocp,
                              (ULONG_PTR) sock,
                              0) == NULL) {
    goto error;
  }

  return sock;

 error:
  closesocket(sock);
  return INVALID_SOCKET;
}


static SOCKET uv__fast_poll_get_peer_socket(uv_loop_t* loop, WSAPROTOCOL_INFOW* protocol_info) {
  int index, i;
  SOCKET peer_socket;

  index = -1;
  for (i = 0; i < ARRAY_SIZE(uv_msafd_provider_ids); i++) {
    if (memcmp((void*) &protocol_info->ProviderId,
               (void*) &uv_msafd_provider_ids[i],
               sizeof protocol_info->ProviderId) == 0) {
      index = i;
    }
  }

  /* Check if the protocol uses an msafd socket. */
  if (1||index < 0) {
    return INVALID_SOCKET;
  }

  /* If we didn't (try) to create a peer socket yet, try to make one. Don't */
  /* try again if the peer socket creation failed earlier for the same */
  /* protocol. */
  peer_socket = loop->poll_peer_sockets[index];
  if (peer_socket == 0) {
    peer_socket = uv__fast_poll_create_peer_socket(loop->iocp, protocol_info);
    loop->poll_peer_sockets[index] = peer_socket;
  }

  return peer_socket;
}


int uv_poll_init_socket(uv_loop_t* loop, uv_poll_t* handle,
    uv_platform_socket_t socket) {
  WSAPROTOCOL_INFOW protocol_info;
  int len;
  SOCKET peer_socket;

  handle->type = UV_POLL;
  handle->socket = socket;
  handle->loop = loop;
  handle->flags = 0;
  handle->events = 0;
  handle->submitted_events = 0;

  /* Obtain the protocol information about the socket first. */
  len = sizeof protocol_info;
  if (getsockopt(socket,
                 SOL_SOCKET,
                 SO_PROTOCOL_INFOW,
                 (char*) &protocol_info,
                 &len) != 0) {
    uv__set_sys_error(loop, WSAGetLastError());
    return -1;
  }

  /* Get the peer socket that is needed to enable fast poll. If the returned */
  /* value is NULL, the protocol is not implemented by MSAFD and we'll have */
  /* to use slow mode. */
  peer_socket = uv__fast_poll_get_peer_socket(loop, &protocol_info);

  if (peer_socket != INVALID_SOCKET) {
    /* Initialize fast poll specific fields. */
    handle->peer_socket = peer_socket;

  } else {
    /* Initialize slow poll specific fields. */
    handle->flags |= UV_HANDLE_POLL_SLOW;
    handle->select_events = 0;
    handle->wait_handle = NULL;

    handle->event_handle = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (handle->event_handle == NULL) {
      uv__set_sys_error(loop, GetLastError());
      return -1;
    }
  }

  /* Initialize the poll req. */
  uv_req_init(loop, (uv_req_t*) &(handle->poll_req));
  handle->poll_req.type = UV_POLL_REQ;
  handle->poll_req.data = handle;

  uv_ref(loop);

  loop->counters.handle_init++;
  loop->counters.poll_init++;

  return 0;
}


static void uv__fast_poll_submit_poll_req(uv_loop_t* loop, uv_poll_t* handle) {
  uv_req_t* req = &handle->poll_req;
  DWORD result;

  assert(handle->events != 0);
  assert(handle->submitted_events == 0);
  assert(!(handle->flags & UV_HANDLE_POLL_CANCELED));

  handle->afd_poll_info.Exclusive = FALSE;
  handle->afd_poll_info.NumberOfHandles = 1;
  handle->afd_poll_info.Timeout.QuadPart = INT64_MAX;
  handle->afd_poll_info.Handles[0].Handle = (HANDLE) handle->socket;
  handle->afd_poll_info.Handles[0].Status = 0;
  handle->afd_poll_info.Handles[0].Events = 0;

  if (handle->events & UV_READABLE)
    handle->afd_poll_info.Handles[0].Events |= AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT | AFD_POLL_ABORT;
  if (handle->events & UV_WRITABLE)
    handle->afd_poll_info.Handles[0].Events |= AFD_POLL_SEND;

  memset(&req->overlapped, 0, sizeof req->overlapped);

  result = uv_msafd_poll(handle->peer_socket, &handle->afd_poll_info, &req->overlapped);
  if (result != 0 && WSAGetLastError() != WSA_IO_PENDING) {
    /* Queue this req, reporting an error. */
    SET_REQ_ERROR(&handle->poll_req, WSAGetLastError());
    uv_insert_pending_req(loop, &handle->poll_req);
  }

  handle->submitted_events = handle->events;
}


/* This function will cancel a pending poll operation by submitting another. */
/* The request will not be queued - we will block until it comes back. */
static int uv__fast_poll_cancel_poll_req(uv_loop_t* loop, uv_poll_t* handle) {
  AFD_POLL_INFO afd_poll_info;
  DWORD result;

  assert(handle->submitted_events != 0);

  if (handle->flags & UV_HANDLE_POLL_CANCELED)
    return 0;

  if (!HasOverlappedIoCompleted(&handle->poll_req.overlapped)) {
    afd_poll_info.Exclusive = FALSE;
    afd_poll_info.NumberOfHandles = 1;
    afd_poll_info.Timeout.QuadPart = 0;
    afd_poll_info.Handles[0].Handle = (HANDLE) handle->socket;
    afd_poll_info.Handles[0].Status = 0;
    afd_poll_info.Handles[0].Events = AFD_POLL_LOCAL_CLOSE;

    result = uv_msafd_poll(handle->peer_socket, &afd_poll_info, NULL);
    if (result != 0) {
      uv__set_sys_error(loop, WSAGetLastError());
      return -1;
    }
  }

  handle->flags |= UV_HANDLE_POLL_CANCELED;
  return 0;
}


static void uv__fast_poll_process_poll_req(uv_loop_t* loop, uv_poll_t* handle, uv_req_t* req) {
  /* Report an error unless the select was just interrupted. */
  if (!REQ_SUCCESS(req)) {
    DWORD error = GET_REQ_SOCK_ERROR(req);
    if (error == WSAEINTR && handle->events != 0) {
      handle->events = 0; /* Stop the watcher */
      uv__set_sys_error(loop, error);
      handle->poll_cb(handle, -1, 0);
    }

  } else if (handle->afd_poll_info.NumberOfHandles >= 1) {
    int reported_events = 0;
    if ((handle->afd_poll_info.Handles[0].Events & (AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT | AFD_POLL_ABORT)) != 0) {
      reported_events |= UV_READABLE;
    }
    if ((handle->afd_poll_info.Handles[0].Events & (AFD_POLL_SEND | AFD_POLL_CONNECT | AFD_POLL_CONNECT_FAIL)) != 0) {
      reported_events |= UV_WRITABLE;
    }

    if ((reported_events & handle->events) != 0) {
      handle->poll_cb(handle, 0, reported_events);
    } else {
      printf("Looks cancelled, sir");
    }
  } else {
    printf("Looks cancelled, sir");
  }
}


static void CALLBACK uv__slow_poll_thread_proc(VOID* arg, BOOLEAN didTimeout) {
  uv_poll_t* handle = (uv_poll_t*) arg;
  assert(!didTimeout);

  /* Unregister the wait. In contradiction to what MSDN says, it's fine to */
  /* unregister a wait from the wait callback itself, as long as the */
  /* WT_EXECUTEINWAITTHREAD flag was specified, and no attempt is made to */
  /* deregister a wait other than the wait whose callback we're currently */
  /* executing. */
  if (!UnregisterWaitEx(handle->wait_handle, NULL)) {
    /* Theoretically UnregisterWaitEx could report ERROR_IO_PENDING, but */
    /* that should never happen when the conditions outlined above are */
    /* satisfied. So if it happens anyway (on Windows RT SM edition Pro?), */
    /* blow up. */
    uv_fatal_error(GetLastError(), "PostQueuedCompletionStatus");
  }

  SET_REQ_SUCCESS(&handle->poll_req);
  POST_COMPLETION_FOR_REQ(handle->loop, &handle->poll_req);
}


static void uv__slow_poll_submit_poll_req(uv_loop_t* loop, uv_poll_t* handle) {
  DWORD eventsel_events;
  int r;

  /* Because WSAEventSelect is edge-triggered wrt writability, we'll use */
  /* select() to find out if the socket is already writable. */
  uv_single_fd_set_t rfds, wfds, efds;
  const struct timeval timeout = {0, 0};

  assert(handle->events != 0);
  assert(handle->submitted_events == 0);
  assert(!(handle->flags & UV_HANDLE_POLL_CANCELED));
  assert(handle->select_events == 0);

  /* Initialize the poll req overlapped structure. */
  memset(&handle->poll_req.overlapped, 0, sizeof handle->poll_req.overlapped);

  /* This function never fails. If an error occurs, it will queue a */
  /* completed req that reports an error. So we can safely update the */
  /* submitted_events field already. */
  handle->submitted_events = handle->events;

  /* This field will be used to report socket state when WSAEventSelect is */
  /* bypassed. */
  handle->select_events = 0;

  /* While we're at it, we might just as well poll for readability. */
  /* if we can detect events without using eventselect, that's nice. */
  if (handle->events & UV_READABLE) {
    rfds.fd_count = 1;
    rfds.fd_array[0] = handle->socket;
  } else {
    rfds.fd_count = 0;
  }

  if (handle->events & UV_WRITABLE) {
    wfds.fd_count = 1;
    wfds.fd_array[0] = handle->socket;
    efds.fd_count = 1;
    efds.fd_array[0] = handle->socket;
  } else {
    wfds.fd_count = 0;
    efds.fd_count = 0;
  }

  r = select(1, (fd_set*) &rfds, (fd_set*) &wfds, (fd_set*) &efds, &timeout);
  if (r == SOCKET_ERROR) {
    /* Queue this req, reporting an error. */
    SET_REQ_ERROR(&handle->poll_req, WSAGetLastError());
    uv_insert_pending_req(loop, &handle->poll_req);
    return;
  }

  if (r > 0) {
    if (rfds.fd_count > 0) {
      assert(rfds.fd_count == 1);
      assert(rfds.fd_array[0] == handle->socket);
      handle->select_events |= UV_READABLE;
    }

    if (wfds.fd_count > 0) {
      assert(wfds.fd_count == 1);
      assert(wfds.fd_array[0] == handle->socket);
      handle->select_events |= UV_WRITABLE;
    } else if (efds.fd_count > 0) {
      assert(efds.fd_count == 1);
      assert(efds.fd_array[0] == handle->socket);
      handle->select_events |= UV_WRITABLE;
    }

    printf("Had a quicky %d\n", handle->select_events);
    assert(handle->select_events != 0);
    SET_REQ_SUCCESS(&handle->poll_req);
    uv_insert_pending_req(loop, &handle->poll_req);
    return;
  }

  eventsel_events = 0;
  if (handle->events & UV_READABLE) {
    eventsel_events |= FD_READ | FD_ACCEPT | FD_CLOSE;
  }
  if (handle->events & UV_WRITABLE) {
    eventsel_events |= FD_WRITE;
  }

  /* Reset the event handle. */
  r = ResetEvent(handle->event_handle);
  if (r == 0) {
     /* Queue this req, reporting an error. */
    SET_REQ_ERROR(&handle->poll_req, GetLastError());
    uv_insert_pending_req(loop, &handle->poll_req);
    return;
  }

  r = WSAEventSelect(handle->socket, handle->event_handle, eventsel_events);
  if (r != 0)  {
    /* Queue this req, reporting an error. */
    SET_REQ_ERROR(&handle->poll_req, WSAGetLastError());
    uv_insert_pending_req(loop, &handle->poll_req);
    return;
  }

  SET_REQ_STATUS(&handle->poll_req, STATUS_PENDING);

  r = RegisterWaitForSingleObject(&handle->wait_handle,
                                  handle->event_handle,
                                  uv__slow_poll_thread_proc,
                                  (void*) handle,
                                  INFINITE,
                                  WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE);
  if (r == 0) {
    /* Queue this req, reporting an error. */
    SET_REQ_ERROR(&handle->poll_req, GetLastError());
    uv_insert_pending_req(loop, &handle->poll_req);
    return;
  }

  send(handle->socket, NULL, -1, 0);

  printf("Doing slow poll %d\n", handle->events);
}


static int uv__slow_poll_cancel_poll_req(uv_loop_t* loop, uv_poll_t* handle) {
  assert(handle->submitted_events != 0);

  /* Don't cancel again if the poll was already canceled. */
  if ((handle->flags & UV_HANDLE_POLL_CANCELED))
    return 0;

  /* If the request short-circtuited in the select path, there's no need to */
  /* force the wait thread to do anything. */
  if (handle->select_events == 0) {
    /* Manually set the event, forcing it to satisfy the wait. */
    printf("Cancelling slow event poll\n");
    if (!SetEvent(handle->event_handle)) {
      uv_fatal_error(GetLastError(), "SetEvent");
    }
  }

  /* Disassociate the socket from the event. This allows the user to close */
  /* the socket when the watcher is stopped. */
  WSAEventSelect(handle->socket, handle->event_handle, 0);

  handle->flags |= UV_HANDLE_POLL_CANCELED;
  return 0;
}


static void uv__slow_poll_process_poll_req(uv_loop_t* loop, uv_poll_t* handle, uv_req_t* req) {
  if (!REQ_SUCCESS(&handle->poll_req)) {
    if (handle->events != 0) {
      handle->events = 0; /* Stop the watcher */
      uv__set_sys_error(loop, GET_REQ_ERROR(&handle->poll_req));
      handle->poll_cb(handle, -1, 0);
    }
  } else {
    /* Always call WSAEnumNetworkEvents - even if the poll was canceled or */
    /* when the WSAEventSelect was never called because we found the socket */
    /* in readable or writable state after calling select(). This is needed */
    /* to atomically reset the event and reset Windows' internal event */
    /* select state. */
    WSANETWORKEVENTS eventsel_reported_events;
    int r;
    int reported_events = handle->select_events;

    handle->select_events = 0;

    r = WSAEnumNetworkEvents(handle->socket, handle->event_handle, &eventsel_reported_events);
    if (r != 0)  {
      if (handle->events != 0) {
        handle->events = 0; /* Stop the watcher */
        uv__set_sys_error(loop, WSAGetLastError());
        handle->poll_cb(handle, -1, 0);
      }
      return;
    }

    if (eventsel_reported_events.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE)) {
      reported_events |= UV_READABLE;
    }
    if (eventsel_reported_events.lNetworkEvents & FD_WRITE) {
      reported_events |= UV_WRITABLE;
      handle->flags |= UV_HANDLE_POLL_ASSUME_WRITABLE;
    }

    if ((reported_events & handle->events) != 0) {
      handle->poll_cb(handle, 0, reported_events);
    } else {
      printf("Poll looks canceled\n");
    }
  }
}


static void uv__poll_submit_poll_req(uv_loop_t* loop, uv_poll_t* handle) {
  if (!(handle->flags & UV_HANDLE_POLL_SLOW)) {
    uv__fast_poll_submit_poll_req(loop, handle);
  } else {
    uv__slow_poll_submit_poll_req(loop, handle);
  }
}

static int uv__poll_cancel_poll_req(uv_loop_t* loop, uv_poll_t* handle) {
  if (!(handle->flags & UV_HANDLE_POLL_SLOW)) {
    return uv__fast_poll_cancel_poll_req(loop, handle);
  } else {
    return uv__slow_poll_cancel_poll_req(loop, handle);
  }
}


static int uv__poll_set(uv_loop_t* loop, uv_poll_t* handle, int events) {
  assert(handle->type == UV_POLL);
  assert(!(handle->flags & UV_HANDLE_CLOSING));
  assert((events & ~(UV_READABLE | UV_WRITABLE)) == 0);

  if (handle->submitted_events != 0) {
    /* A poll has already been submitted. We cannot have two outstanding */
    /* poll requests simultaneously, so we either cancel one or just wait */
    /* for it to complete. */

    /* If the submitted poll request is looking for everything that the */
    /* user is interested in, just ignore. It might eventually report an */
    /* an event that the user is not interested in, but if that happens we */
    /* can just ignore it and submit another poll with the correct poll */
    /* mask. */

    /* If the user wants to be notified of events that are not */
    /* included in the submitted poll mask, the poll operation has to be */
    /* interrupted or it might block indefinitely. Be careful not to cancel */
    /* a poll request that already has been canceled. */
    if ((handle->submitted_events & events) != events &&
        uv__poll_cancel_poll_req(loop, handle) != 0) {
      return -1;
    }

    handle->events = events;
    return 0;
  }

  handle->events = events;
  if (events) {
    uv__poll_submit_poll_req(handle->loop, handle);
  }

  return 0;
}


int uv_poll_stop(uv_poll_t* handle) {
  return uv__poll_set(handle->loop, handle, 0);
}


int uv_poll_start(uv_poll_t* handle, int events, uv_poll_cb cb) {
  if (uv__poll_set(handle->loop, handle, events) != 0) {
    return -1;
  }

  handle->poll_cb = cb;
  return 0;
}


void uv_process_poll_req(uv_loop_t* loop, uv_poll_t* handle, uv_req_t* req) {
  handle->submitted_events = 0;
  handle->flags &= ~UV_HANDLE_POLL_CANCELED;

  if (!(handle->flags & UV_HANDLE_POLL_SLOW)) {
    uv__fast_poll_process_poll_req(loop, handle, req);
  } else {
    uv__slow_poll_process_poll_req(loop, handle, req);
  }

  if (handle->events != 0 &&
      handle->submitted_events == 0) {
    uv__poll_submit_poll_req(loop, handle);
  } else if ((handle->flags & UV_HANDLE_CLOSING) &&
             !handle->submitted_events) {
    uv_want_endgame(loop, (uv_handle_t*) handle);
  }
}


void uv_poll_close(uv_loop_t* loop, uv_poll_t* handle) {
  if (handle->submitted_events == 0) {
    uv_want_endgame(loop, (uv_handle_t*) handle);
  } else {
    uv__poll_cancel_poll_req(handle->loop, handle);
  }
}


void uv_poll_endgame(uv_loop_t* loop, uv_poll_t* handle) {
  if (handle->flags & UV_HANDLE_CLOSING &&
      handle->submitted_events == 0) {
    assert(!(handle->flags & UV_HANDLE_CLOSED));
    handle->flags |= UV_HANDLE_CLOSED;

    if (handle->flags & UV_HANDLE_POLL_SLOW) {
      CloseHandle(handle->event_handle);
    }

    if (handle->close_cb) {
      handle->close_cb((uv_handle_t*)handle);
    }

    uv_unref(loop);
  }
}
