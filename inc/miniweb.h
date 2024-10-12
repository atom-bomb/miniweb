/*
 * miniweb.h
 *
 * simple http(s) server for simple systems
 */
#ifndef MINIWEB_H
#define MINIWEB_H 1

#include <stdbool.h>
#include <stddef.h>
#include <arpa/inet.h>

typedef enum miniweb_err_e {
  MINIWEB_ERR_OK,
  MINIWEB_ERR_FAIL,
  MINIWEB_ERR_MEM,
  MINIWEB_ERR_IO,
  MINIWEB_ERR_SOCK,
  MINIWEB_ERR_SSL
} miniweb_err_t;

typedef struct miniweb_header_list_s {
  char *key;
  char *value;
  struct miniweb_header_list_s *next;
} miniweb_header_list_t;

typedef struct miniweb_server_s *miniweb_server_ptr;
typedef struct miniweb_conn_s *miniweb_conn_ptr;

typedef bool (*miniweb_handler_cb_t)(
  miniweb_conn_ptr con,
  const char *method,
  const char *path,
  miniweb_header_list_t *headers,
  char *body,
  size_t length,
  void *userdata);

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
  size_t count);

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
  size_t count);

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
  void* userdata);

/*
 * miniweb_init
 *
 * setup a http server on the given port
 *
 * miniweb - pointer to get new miniweb instance
 * addr - network order address on which to listen for connections
 * port - network order port number on which to listen for connections
 *
 * returns miniweb_err_t
 */
miniweb_err_t
miniweb_init(
  miniweb_server_ptr *miniweb,
  in_addr_t addr,
  in_port_t port);

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
  const char *key_path);

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
  miniweb_server_ptr miniweb);

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
  miniweb_server_ptr miniweb);

#endif /* MINIWEB_H */

/* vim: set ts=2 sw=2 tw=80 co=82 ft=c ff=unix et: */
