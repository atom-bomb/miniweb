/*
 * miniweb.h
 *
 * simple http(s) server for simple systems
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>

#ifdef MINIWEB_SSL_ENABLE
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "debug_print.h"

#include "miniweb.h"

#define MINIWEB_REQ_BUFFER_SIZE 256
#define MINIWEB_POLL_TIMEOUT 10000
#define MINIWEB_METHOD_MAX_LEN 10
#define MINIWEB_URI_MAX_LEN 128
#define MINIWEB_VERSION_MAX_LEN 10

#define MINIWEB_CMD_QUIT 1ll

/* linked list node for tracking registered handler callbacks */
typedef struct miniweb_handler_list_s {
  const char *method;
  const char *path;
  void *userdata;
  miniweb_handler_cb_t callback;
  struct miniweb_handler_list_s *next;
} miniweb_handler_list_t;

/* private data for each server instance */
typedef struct miniweb_server_s {
  int server_msg_fd;
  int server_sockfd;

#ifdef MINIWEB_SSL_ENABLE
	SSL_CTX *ssl_ctx;
#endif /* MINIWEB_SSL_ENABLE */

  volatile bool server_done;
  pthread_t server_thread;

  miniweb_handler_list_t *handlers;
} miniweb_server_t;

/* handles for reading and writing to a client connection */
typedef struct miniweb_conn_s {
  int sockfd;
#ifdef MINIWEB_SSL_ENABLE
  SSL *ssl;
#endif /* MINIWEB_SSL_ENABLE */
} miniweb_conn_t;

/*
 * miniweb_free_header_list
 *
 * head - head of header list to free
 *
 * returns void
 */
static void
miniweb_free_header_list(
  miniweb_header_list_t **head) {

  ASSERT_ABORT(head && *head);
  TRACE_PRINTF("\n");

  if (*head != NULL) {
    if ((*head)->key)
      free((*head)->key);

    if ((*head)->value)
      free((*head)->value);

    if ((*head)->next)
      miniweb_free_header_list(&((*head)->next));

    free(*head);
    *head = NULL;
  } /* if */
} /* miniweb_free_header_list */

/*
 * miniweb_add_header
 *
 * head - head of header list to which a new header shall be added
 * key - name of new header
 * value - value of new header
 *
 * returns void
 */
static void
miniweb_add_header(
  miniweb_header_list_t **head,
  const char *key,
  const char *value) {

  miniweb_header_list_t *new_node = NULL;
  miniweb_header_list_t *current = NULL;

  ASSERT_ABORT(key);
  ASSERT_ABORT(value);

  TRACE_PRINTF("\n");

  new_node = malloc(sizeof(miniweb_header_list_t));

  if (new_node) {
    new_node->key = strdup(key);
    new_node->value = strdup(value);
    new_node->next = NULL;

    ASSERT_ABORT(new_node->key && new_node->value);

    if (*head == NULL) {
      *head = new_node;
    } else {
      current = *head;

      while (current->next)
        current = current->next;

      current->next = new_node;
    } /* else */
  } else
    ERROR_PRINTF("OOM\n");
} /* miniweb_add_header */

/*
 * miniweb_handle_connection
 *
 * handle a request on a given socket
 *
 * miniweb - pointer to miniweb instance
 * conn - the new connection
 *
 * returns void
 */
static void
miniweb_handle_connection(
  miniweb_server_ptr miniweb,
  miniweb_conn_ptr conn) {

  char req_buffer[MINIWEB_REQ_BUFFER_SIZE];
  char *read_ptr = NULL;
  size_t read_len = 0;
  int bytes_recvd = 0;
  char method[MINIWEB_METHOD_MAX_LEN],
       uri[MINIWEB_URI_MAX_LEN],
       version[MINIWEB_VERSION_MAX_LEN];
  miniweb_header_list_t *req_headers = NULL;
  char *req_body = NULL;
  size_t content_len = 0;

  bool receiving = true;
  bool got_req = false;
  char *parse_ptr = NULL;
  size_t parse_len = 0;

  int bytes_sent = 0;
  const char resp_buffer[] = "HTTP/1.0 404 Not Found\r\n"
                             "Server: miniweb\r\n"
                             "Content-Length: 11\r\n"
                             "Content-Type: text/plain\r\n\r\n"
                             "Not Found\r\n";

  ASSERT_ABORT(miniweb);
  ASSERT_ABORT(conn);

  TRACE_PRINTF("\n");

  read_ptr = req_buffer;
  read_len = sizeof(req_buffer) - 1;

  while (receiving) {
    req_buffer[MINIWEB_REQ_BUFFER_SIZE - 1] = '\0';
    bytes_recvd = miniweb_conn_read(conn, read_ptr, read_len);
    if (bytes_recvd < 0) {
      receiving = false;
      break;
    } /* if */

    parse_ptr = req_buffer;
    parse_len = 0;

    while (receiving && parse_len < bytes_recvd) {
      if (false == got_req) {
        char *method_arg = NULL;
        char *uri_arg = NULL;
        char *version_arg = NULL;

        method_arg = strsep(&parse_ptr, " ");
        if (method_arg)
          strncpy(method, method_arg, sizeof(method) - 1);

        uri_arg = strsep(&parse_ptr, " ");

        if (uri_arg)
          strncpy(uri, uri_arg, sizeof(uri) - 1);

        version_arg = strsep(&parse_ptr, "\r\n");
        if (version_arg)
          strncpy(version, version_arg, sizeof(version) - 1);

        if (NULL == parse_ptr)
          parse_len = bytes_recvd;
        else {
          if (*parse_ptr == '\n')
            parse_ptr++;

          parse_len = parse_ptr - req_buffer;
        } /* else */

        got_req = (method_arg && uri_arg && version_arg);
        if (got_req) {
          DEBUG_PRINTF("%s %s %s\n", method, uri, version);
        } else {
          ERROR_PRINTF("Request Parse Error\n");
        } /* else */
      } else {
        char *this_key = NULL;
        char *this_value = NULL;

        if (bytes_recvd - parse_len >= 2) {
          if (parse_ptr[0] == '\r' && parse_ptr[1] == '\n') {
            receiving = false;
            parse_ptr += 2;
            parse_len += 2;
            break;
          } /* if */
        } /* if */

        this_key = strsep(&parse_ptr, ":");
        if (NULL == parse_ptr) {
          size_t savelen = strlen(this_key);

          memmove(req_buffer, this_key, savelen);
          read_ptr = req_buffer + savelen;
          read_len = sizeof(req_buffer) - savelen - 1;
          parse_len = bytes_recvd;
          break;
        } /* if */

        while (*parse_ptr == ' ')
          parse_ptr++;

        this_value = strsep(&parse_ptr, "\r\n");
        if (NULL == parse_ptr) {
          size_t savelen = strlen(this_value);

          memmove(req_buffer, this_value, savelen);
          read_ptr = req_buffer + savelen;
          read_len = sizeof(req_buffer) - savelen - 1;
          parse_len = bytes_recvd;
          break;
        } /* if */

        if (*parse_ptr == '\n')
          parse_ptr++;

        DEBUG_PRINTF("Header %s->%s\n", this_key, this_value);
        miniweb_add_header(&req_headers, this_key, this_value);
        if (0 == strcasecmp(this_key, "Content-Length")) {
          content_len = atoi(this_value);
        } /* if */

        parse_len = parse_ptr - req_buffer;
      } /* else */
    } /* while */
  } /* while */

  if (content_len) {
    req_body = malloc(content_len);

    if (req_body) {
      read_len = content_len - (bytes_recvd - parse_len);
      memmove(req_body, parse_ptr, bytes_recvd - parse_len);
      if (read_len > 0) {
        read_ptr = req_body + bytes_recvd - parse_len;
        bytes_recvd = miniweb_conn_read(conn, read_ptr, read_len);
      } /* if */
    } /* if */
  } /* if */

  miniweb_handler_list_t *current = miniweb->handlers;
  bool handled = false;

  while (current) {
    if ((0 == strcmp(method, current->method)) &&
       (0 == strncmp(uri, current->path, strlen(current->path)))) {
      DEBUG_PRINTF("Calling %s %s\n", current->method, current->path);
      handled = (*current->callback)(conn, method, uri, req_headers,
        req_body, content_len, current->userdata);
      if (handled)
        break;
    } /* if */

    current = current->next;
  } /* while */

  if (!handled) {
    DEBUG_PRINTF("Default handler\n");
    bytes_sent = miniweb_conn_write(conn, resp_buffer, sizeof(resp_buffer) - 1);
    DEBUG_PRINTF("%d bytes sent\n", bytes_sent);
  } /* if */

  miniweb_free_header_list(&req_headers);

  if (req_body)
    free(req_body);
} /* miniweb_handle_connection */

/*
 * miniweb_server_thread
 *
 * worker thread that accepts connections for miniweb
 *
 * miniweb - pointer to miniweb instance
 *
 * returns void*
 */
static void*
miniweb_server_thread(
  void *pmw) {

  int poll_ret = 0;
  struct pollfd poll_fds[2];
  uint64_t msg;
  struct sockaddr_in host_addr;
  int host_addrlen = sizeof(host_addr);
  miniweb_server_ptr miniweb = (miniweb_server_ptr)pmw;
  miniweb_conn_t conn;

  ASSERT_ABORT(miniweb);

  while (!miniweb->server_done) {
    poll_fds[0].fd = miniweb->server_msg_fd;
    poll_fds[0].events = POLLIN;
    poll_fds[0].revents = 0;

    poll_fds[1].fd = miniweb->server_sockfd;
    poll_fds[1].events = POLLIN;
    poll_fds[1].revents = 0;

    poll_ret = poll(poll_fds, 2, MINIWEB_POLL_TIMEOUT);

    if (poll_ret == 0)
      continue;

    if (poll_fds[0].revents) {
      if (-1 != read(miniweb->server_msg_fd, &msg, sizeof(msg)))
        continue;
    } /* if */

    conn.sockfd = accept(miniweb->server_sockfd,
               (struct sockaddr *)&host_addr,
               (socklen_t *)&host_addrlen);
    if (conn.sockfd < 0)
      continue;

#ifdef MINIWEB_SSL_ENABLE
    if (miniweb->ssl_ctx) {
      conn.ssl = SSL_new(miniweb->ssl_ctx);
      SSL_set_fd(conn.ssl, conn.sockfd);

	    if (1 != SSL_accept(conn.ssl)) {
        SSL_free(conn.ssl);
        close(conn.sockfd);
        continue;
      } /* if */
    } /* if */
#endif

    miniweb_handle_connection(miniweb, &conn);

#ifdef MINIWEB_SSL_ENABLE
    if (miniweb->ssl_ctx)
      SSL_free(conn.ssl);
#endif

    close(conn.sockfd);
  } /* while */

  return NULL;
} /* miniweb_server_thread */

/*
 * miniweb_conn_write
 *
 * write up to count bytes from buf to conn
 *
 * conn - miniweb connection to write upon
 * buf - buffer to read from
 * count - how many bytes to send
 *
 * returns number of bytes written or < 0 on error
 */
ssize_t 
miniweb_conn_write(
  miniweb_conn_ptr conn,
  const void *buf,
  size_t count) {

  ssize_t ret = -1;

  ASSERT_ABORT(conn);
  ASSERT_ABORT(buf);

  TRACE_PRINTF("\n");

#ifdef MINIWEB_SSL_ENABLE
  if (conn->ssl) {
    ret = SSL_write(conn->ssl, buf, count);
  } else
#endif
  ret = write(conn->sockfd, buf, count);

  return ret;
} /* miniweb_conn_write */

/*
 * miniweb_conn_read
 *
 * read up to count bytes info buf from conn
 *
 * conn - miniweb connection from which to read
 * buf - buffer to store data
 * count - how many bytes to receive
 *
 * returns number of bytes read or < 0 on error
 */
ssize_t 
miniweb_conn_read(
  miniweb_conn_ptr conn,
  void *buf,
  size_t count) {

  ssize_t ret = -1;

  ASSERT_ABORT(conn);
  ASSERT_ABORT(buf);

  TRACE_PRINTF("\n");

#ifdef MINIWEB_SSL_ENABLE
  if (conn->ssl) {
    ret = SSL_read(conn->ssl, buf, count);
  } else
#endif
  ret = read(conn->sockfd, buf, count);

  return ret;
} /* miniweb_conn_read */

/*
 * miniweb_register_handler
 *
 * register a function to handle calls to a given endpoint
 *
 * miniweb - pointer to miniweb instance
 * handler_fn - function to callback
 * method - method to match for callback
 * path - uri path to match for callback
 * userdata - pointer to pass to callback
 *
 * returns miniweb_err_t
 */
miniweb_err_t
miniweb_register_handler(
  miniweb_server_ptr miniweb,
  miniweb_handler_cb_t handler_fn,
  const char* method,
  const char* path,
  void* userdata) {

  miniweb_handler_list_t *current = NULL;
  miniweb_handler_list_t *new_handler = NULL;

  ASSERT_ABORT(miniweb);
  ASSERT_ABORT(handler_fn);
  ASSERT_ABORT(method);
  ASSERT_ABORT(path);

  TRACE_PRINTF("\n");

  new_handler = malloc(sizeof(miniweb_handler_list_t));

  if (NULL == new_handler) {
    ERROR_PRINTF("OOM\n");
    return MINIWEB_ERR_MEM;
  } /* if */

  memset(new_handler, 0, sizeof(miniweb_handler_list_t));

  new_handler->method = strdup(method);
  new_handler->path = strdup(path);
  new_handler->userdata = userdata;
  new_handler->callback = handler_fn;
  new_handler->next = NULL;

  ASSERT_ABORT(new_handler->method && new_handler->path);

  if (miniweb->handlers == NULL) {
    miniweb->handlers = new_handler;
  } else {
    current = miniweb->handlers;

    while (current->next != NULL)
      current = current->next;

    current->next = new_handler;
  } /* else */

  return MINIWEB_ERR_OK;
} /* miniweb_register_handler */

/*
 * miniweb_init
 *
 * setup a http server on the given port
 *
 * miniweb_new - pointer to get new miniweb instance
 * addr - network order address on which to listen for connections
 * port - network order port number on which to listen for connections
 *
 * returns miniweb_err_t
 */
miniweb_err_t
miniweb_init(
  miniweb_server_ptr *miniweb_new,
  in_addr_t addr,
  in_port_t port) {

  miniweb_err_t ret = MINIWEB_ERR_FAIL;
  int reuse = 1;

  struct sockaddr_in host_addr;
  int host_addrlen = sizeof(host_addr);
  miniweb_server_ptr miniweb = NULL;

  ASSERT_ABORT(miniweb_new);

  TRACE_PRINTF("\n");

  miniweb = malloc(sizeof(struct miniweb_server_s));
  if (NULL == miniweb) {
    ERROR_PRINTF("OOM\n");
    ret = MINIWEB_ERR_MEM;
    goto bail;
  } /* if */

  memset(miniweb, 0, sizeof(miniweb_server_t));
  miniweb->server_sockfd = -1;
  miniweb->server_msg_fd = -1;

  miniweb->server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (miniweb->server_sockfd == -1) {
    ERROR_PRINTF("socket failed\n");
    goto bail;
  } /* if */

  if (setsockopt(miniweb->server_sockfd, SOL_SOCKET,
    SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    WARNING_PRINTF("setsockopt(SO_REUSEADDR) failed");

#ifdef SO_REUSEPORT
  if (setsockopt(miniweb->server_sockfd, SOL_SOCKET,
    SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
    WARNING_PRINTF("setsockopt(SO_REUSEPORT) failed");
#endif

  DEBUG_PRINTF("binding %d.%d.%d.%d:%d\n",
    (addr & 0x000000ff),
    (addr & 0x0000ff00) >> 8,
    (addr & 0x00ff0000) >> 16,
    (addr & 0xff000000) >> 24,
    ntohs(port));

  host_addr.sin_family = AF_INET;
  host_addr.sin_port = port;
  host_addr.sin_addr.s_addr = addr;

  if (bind(miniweb->server_sockfd,
     (struct sockaddr *)&host_addr, host_addrlen) != 0) {
    ERROR_PRINTF("bind failed\n");
    goto bail;
  } /* if */

  if (listen(miniweb->server_sockfd, SOMAXCONN) != 0) {
    ERROR_PRINTF("listen failed\n");
    goto bail;
  } /* if */

  ret = MINIWEB_ERR_OK;

bail:
  if (miniweb) {
    if (MINIWEB_ERR_OK != ret)
      free(miniweb);
    else
      *miniweb_new = miniweb;
  } /* if */

  return ret;
} /* miniweb_init */

#ifdef MINIWEB_SSL_ENABLE

/*
 * miniweb_ssl_init
 *
 * setup a https server on the given port
 *
 * miniweb - pointer to get new miniweb instance
 * addr - network order address on which to listen for connections
 * port - network order port number on which to listen for connections
 * cert_path - path to SSL certificate file
 * key_path - path to private key
 *
 * returns miniweb_err_t
 */
miniweb_err_t
miniweb_ssl_init(
  miniweb_server_ptr *miniweb,
  in_addr_t addr,
  in_port_t port,
  const char *cert_path,
  const char *key_path) {

  miniweb_err_t ret = MINIWEB_ERR_FAIL;
	const SSL_METHOD *method;

  ASSERT_ABORT(miniweb);
  ASSERT_ABORT(cert_path);

  TRACE_PRINTF("\n");

  ret = miniweb_init(miniweb, addr, port);
  if (MINIWEB_ERR_OK != ret)
    goto bail;

  ret = MINIWEB_ERR_FAIL;

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
    
	method = TLS_server_method();
  (*miniweb)->ssl_ctx = SSL_CTX_new(method);

  if (NULL == (*miniweb)->ssl_ctx) {
    ERROR_PRINTF("SSL_CTX_new failed\n");
    goto bail;
  } /* if */
	
	SSL_CTX_set_cipher_list((*miniweb)->ssl_ctx, "ALL:eNULL");
   
  if (1 != SSL_CTX_load_verify_locations((*miniweb)->ssl_ctx,
      cert_path, key_path)) {
    ERROR_PRINTF("SSL_CTX_load_verify_locations failed\n");
    ret = MINIWEB_ERR_IO;
    goto bail;
  } /* if */

  if (1 != SSL_CTX_set_default_verify_paths((*miniweb)->ssl_ctx)) {
    ERROR_PRINTF("SSL_CTX_set_default_verify_paths failed\n");
    goto bail;
  } /* if */

  if (0 >= SSL_CTX_use_certificate_file((*miniweb)->ssl_ctx,
      cert_path, SSL_FILETYPE_PEM)) {
    ERROR_PRINTF("SSL_CTX_use_certificate_file failed\n");
    ret = MINIWEB_ERR_IO;
    goto bail;
  } /* if */

  if (0 >= SSL_CTX_use_PrivateKey_file((*miniweb)->ssl_ctx,
      key_path, SSL_FILETYPE_PEM)) {
    ERROR_PRINTF("SSL_CTX_use_PrivateKey_file failed\n");
    ret = MINIWEB_ERR_IO;
    goto bail;
  } /* if */

  if (!SSL_CTX_check_private_key((*miniweb)->ssl_ctx)) {
    ERROR_PRINTF("SSL_CTX_check_private_key failed\n");
    ret = MINIWEB_ERR_SSL;
    goto bail;
  } /* if */

  ret = MINIWEB_ERR_OK;

bail: 
  if (MINIWEB_ERR_OK != ret) {
    miniweb_fini(*miniweb);
    *miniweb = NULL;
  } /* if */

  return ret;
} /* miniweb_ssl_init */

#endif

/*
 * miniweb_start
 *
 * start a server that has already been setup
 *
 * miniweb - server to start
 *
 * returns miniweb_err_t
 */
miniweb_err_t
miniweb_start(
  miniweb_server_ptr miniweb) {

  miniweb_err_t ret = MINIWEB_ERR_FAIL;

  ASSERT_ABORT(miniweb);

  TRACE_PRINTF("\n");

  miniweb->server_done = false;
  miniweb->server_msg_fd = eventfd(0, 0);

  if (0 == pthread_create(&miniweb->server_thread, NULL,
    miniweb_server_thread, miniweb)) {
    ret = MINIWEB_ERR_OK;
  } else {
    ERROR_PRINTF("failed to create server thread\n");
  } /* else */

  return ret;
} /* miniweb_start */

/*
 * miniweb_fini
 *
 * shutdown http server and free any allocated resources
 *
 * miniweb - pointer to miniweb instance
 *
 * returns void
 */
void
miniweb_fini(
  miniweb_server_ptr miniweb) {

  uint64_t quit_val = MINIWEB_CMD_QUIT;
  miniweb_handler_list_t *current = NULL;
  miniweb_handler_list_t *next = NULL;

  ASSERT_ABORT(miniweb);

  TRACE_PRINTF("\n");

  if (miniweb->server_thread) {
    miniweb->server_done = true;

    if (-1 == write(miniweb->server_msg_fd, &quit_val, sizeof(quit_val))) {
      WARNING_PRINTF("send quit msg failed\n");
    } /* if */

    pthread_join(miniweb->server_thread, NULL);
    miniweb->server_thread = 0;
  } /* if */

  if (miniweb->server_sockfd != -1) {
    close(miniweb->server_sockfd);
    miniweb->server_sockfd = -1;
  } /* if */

  if (miniweb->server_msg_fd != -1) {
    close(miniweb->server_msg_fd);
    miniweb->server_msg_fd = -1;
  } /* if */

  if (miniweb->handlers) {
    current = miniweb->handlers;

    while (current) {
      free((void*)current->method);
      free((void*)current->path);
      next = current->next;
      free(current);
      current = next;
    } /* while */

    miniweb->handlers = NULL;
  } /* if */

#ifdef MINIWEB_SSL_ENABLE
  if (miniweb->ssl_ctx) {
    SSL_CTX_free(miniweb->ssl_ctx);
    miniweb->ssl_ctx = NULL;
  } /* if */
#endif /* MINIWEB_SSL_ENABLE */

  free(miniweb);
} /* miniweb_fini */

/* vim: set ts=2 sw=2 tw=80 co=82 ft=c ff=unix et: */
