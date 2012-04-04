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


int uv_poll_init(uv_loop_t* loop, uv_poll_t* handle, int fd) {
  return uv_poll_init_socket(loop, handle, (SOCKET) _get_osfhandle(fd));
}

int uv_poll_init_socket(uv_loop_t* loop, uv_poll_t* handle,
    uv_platform_socket_t socket) {
  handle->type = UV_POLL;
  handle->socket = INVALID_SOCKET;
  handle->loop = loop;
  handle->flags = 0;
  handle->events = 0;

  uv_req_init(loop, (uv_req_t*) &(handle->poll_req));
  handle->poll_req.type = UV_POLL_REQ;
  handle->poll_req.data = handle;

  uv_ref(loop);

  loop->counters.handle_init++;
  loop->counters.poll_init++;

 /* TODO: check if the socket is an msafd protocol. */


  /* Try to associate with IOCP */
  if (CreateIoCompletionPort((HANDLE) socket,
                             loop->iocp,
                             (ULONG_PTR) socket,
                             0) == NULL) {
    /* Association failed. */
    /* TODO: Use fallback mode. */
    uv_fatal_error(GetLastError(), "CreateIoCompletionPort");
  }

  return 0;
}


static void uv__poll_submit_poll_request(uv_loop_t* loop, uv_poll_t* handle) {
  uv_req_t* req = &handle->poll_req;
  DWORD result;

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

  result = uv_msafd_poll(&handle->afd_poll_info, &req->overlapped);
  if (result != 0) {
    /* Queue this req, reporting an error. */
    SET_REQ_ERROR(&handle->poll_req, WSAGetLastError());
  }

  handle->submitted_events = handle->events;
}


/* This function will cancel a pending poll operation by submitting another. */
/* The request will not be queued - we will block until it comes back. */
static int uv__poll_pushout_poll_request(uv_loop_t* loop, uv_poll_t* handle) {
  AFD_POLL_INFO afd_poll_info;
  DWORD result;

  afd_poll_info.Exclusive = FALSE;
  afd_poll_info.NumberOfHandles = 1;
  afd_poll_info.Timeout.QuadPart = 0;
  afd_poll_info.Handles[0].Handle = (HANDLE) handle->socket;
  afd_poll_info.Handles[0].Status = 0;
  afd_poll_info.Handles[0].Events = AFD_POLL_LOCAL_CLOSE;
  
  result = uv_msafd_poll(&afd_poll_info, NULL);
  if (result != 0) {
    uv__set_sys_error(loop, WSAGetLastError());
    return -1;
  }

  return 0;
}


static int uv__poll_set(uv_loop_t* loop, uv_poll_t* handle, int events) {
  assert(handle->type == UV_POLL);
  assert(!(handle->flags & UV_HANDLE_CLOSING));
  assert((events & ~(UV_READABLE | UV_WRITABLE)) == 0);

  if (events == handle->events) {
    /* Nothing changed */
    return 0;
  }
 
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
        !(handle->flags & UV_HANDLE_POLL_CANCELED) && 
        uv__poll_pushout_poll_request(loop, handle) != 0) {
      return -1;
    }

    handle->events = events;
    return 0;
  }

  handle->events = events;
  uv__poll_submit_poll_request(handle->loop, handle);

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
}


void uv_process_poll_req(uv_loop_t* loop, uv_poll_t* handle, uv_req_t* req) {
  handle->submitted_events = 0;

  /* Report an error unless the select was just interrupted by poll. */
  if (!REQ_SUCCESS(req)) {
    DWORD error = GET_REQ_SOCK_ERROR(req);
    if (error != WSAEINTR) {
      handle->events = 0;
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

    if (reported_events & handle->events) {
      handle->poll_cb(handle, 0, reported_events);
    }
  }

 out:
  if (handle->events != 0 &&
      handle->submitted_events == 0) {
    uv__poll_submit_poll_request(loop, handle);
  } else if ((handle->flags & UV_HANDLE_CLOSING) &&
              !handle->submitted_events) {
    uv_want_endgame(loop, (uv_handle_t*) handle);
  }
}


void uv_poll_endgame(uv_loop_t* loop, uv_poll_t* handle) {
  if (handle->flags & UV_HANDLE_CLOSING &&
      handle->submitted_events == 0) {
    assert(!(handle->flags & UV_HANDLE_CLOSED));
    handle->flags |= UV_HANDLE_CLOSED;

    if (handle->close_cb) {
      handle->close_cb((uv_handle_t*)handle);
    }

    uv_unref(loop);
  }
}


void uv_poll_close(uv_loop_t* loop, uv_poll_t* handle) {
  if (handle->submitted_events == 0) {
    uv_want_endgame(loop, (uv_handle_t*) handle);
  } else {
    uv__poll_pushout_poll_request(handle->loop, handle);
  }
}