
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <signal.h>
#include <fcntl.h>

#include "debug_print.h"
#include "miniweb.h"

#define MINIWEB_MAIN_XFER_BUF_SIZE 4096

#ifdef ENABLE_DEBUG_PRINTS
debug_print_t debug_print;
#endif

static sem_t miniweb_main_server_sem;

static void
miniweb_main_signal_handler(
  int signum) {
  sem_post(&miniweb_main_server_sem);
} /* miniweb_main_signal_handler */

static bool
miniweb_main_get_handler_cb(
  miniweb_conn_ptr con,
  const char *method,
  const char *path,
  miniweb_header_list_t *headers,
  char *body,
  size_t length,
  void *userdata) {

  bool handled = false;
  char *cwd = NULL;
  char *asset_path = NULL;
  ssize_t asset_path_len = 0;
  struct stat statbuf;
  ssize_t bytes_sent = 0;
  char *resp_hdr = NULL;
  ssize_t resp_hdr_len = 0;
  int fd_asset = -1;
  char *xfer_buf = NULL;
  ssize_t xfer_size = 0;
  off_t bytes_left = 0;

  const char resp_fmt[] = "HTTP/1.0 200 OK\r\n"
                  "Server: miniweb\r\n"
                  "Content-Length: %ld\r\n\r\n";

  ASSERT_ABORT(method);
  ASSERT_ABORT(path);

  TRACE_PRINTF("\n");

  if (strstr(path, "/../")) {
    WARNING_PRINTF("url includes relative path\n");
    goto bail;
  } /* if */

  cwd = getcwd(NULL, 0);
  ASSERT_ABORT(cwd);

  asset_path_len = asprintf(&asset_path, "%s%s", cwd, path);
  if (0 >= asset_path_len)
    goto bail;

  if (0 > stat(asset_path, &statbuf)) {
    WARNING_PRINTF("can't stat %s\n", asset_path);
    goto bail;
  } /* if */

  if (S_IFREG != (statbuf.st_mode & S_IFMT)) {
    WARNING_PRINTF("%s is not a regular file\n", asset_path);
    goto bail;
  } /* if */

  resp_hdr_len = asprintf(&resp_hdr, resp_fmt, statbuf.st_size);
  if (0 >= resp_hdr_len)
    goto bail;

  DEBUG_PRINTF("sending header\n");
  bytes_sent = miniweb_conn_write(con, resp_hdr, resp_hdr_len);
  if (0 >= bytes_sent) {
    WARNING_PRINTF("failed to send response header\n");
    goto bail;
  } /* if */
  DEBUG_PRINTF("%ld bytes sent\n", bytes_sent);

  fd_asset = open(asset_path, O_RDONLY);
  if (fd_asset < 0) {
    WARNING_PRINTF("failed to open %s\n", asset_path);
    goto bail;
  } /* if */

  xfer_buf = malloc(MINIWEB_MAIN_XFER_BUF_SIZE);
  if (NULL == xfer_buf) {
    WARNING_PRINTF("failed to alloc xfer buffer\n");
    goto bail;
  } /* if */ 

  bytes_left = statbuf.st_size;

  while (bytes_left) {
    xfer_size = (bytes_left < MINIWEB_MAIN_XFER_BUF_SIZE ?
      bytes_left : MINIWEB_MAIN_XFER_BUF_SIZE);

    xfer_size = read(fd_asset, xfer_buf, xfer_size);
    if (xfer_size < 0) {
      WARNING_PRINTF("read failed\n");
      goto bail;
    } /* if */

    xfer_size = miniweb_conn_write(con, xfer_buf, xfer_size);
    if (xfer_size < 0) {
      WARNING_PRINTF("send failed\n");
      goto bail;
    } /* if */

    bytes_left -= xfer_size;
  } /* while */

  handled = true;

bail:
  if (xfer_buf)
    free(xfer_buf);

  if (fd_asset >= 0)
    close(fd_asset);

  if (resp_hdr)
    free(resp_hdr);

  if (cwd)
    free(cwd);

  if (asset_path)
    free(asset_path);

  return handled;
} /* miniweb_main_get_handler_cb */

int
main(
  int argc,
  char **argv) {

  int ret = 0;
  bool show_help = false;
  char opt;
  extern char *optarg;
  extern int optind, optopt, opterr;

  in_addr_t server_addr;
  in_port_t server_port;
  miniweb_server_ptr miniweb = NULL;
  struct sigaction sa;
  
  server_port = 0;
  server_addr = 0;
  sem_init(&miniweb_main_server_sem, 0, 0);

  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = miniweb_main_signal_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);

#ifdef ENABLE_DEBUG_PRINTS
  debug_print.fp = stdout;
#endif

#ifdef MINIWEB_SSL_ENABLE
  const char* cert_path = NULL;
  const char* key_path = NULL;

  while ((opt = getopt(argc, argv, "p:a:c:k:vh?")) != -1) {
#else
  while ((opt = getopt(argc, argv, "p:a:vh?")) != -1) {
#endif
    switch(opt) {
      case 'p':
        server_port = htons((uint16_t)strtoul(optarg, NULL, 0));
        break;

      case 'a':
        server_addr = inet_addr(optarg);
        break;

#ifdef MINIWEB_SSL_ENABLE
      case 'c':
        cert_path = optarg;
        break;

      case 'k':
        key_path = optarg;
        break;
#endif /* MINIWEB_SSL_ENABLE */

      case 'v':
#ifdef ENABLE_DEBUG_PRINTS
        debug_print.level++;
#endif
        break;

      case '?':
      case 'h':
        show_help = true;
        break;

      default:
        fprintf(stderr, "unknown option: %c\n", opt);
        show_help = true;
        break;
    } /* switch */
  } /* while */

  if (show_help) {
    fprintf(stderr, "%s usage:\n", argv[0]);
    fprintf(stderr, "----------------------------------------------\n");
    fprintf(stderr, "-p <port>            : serve on port\n");
    fprintf(stderr, "-a <addr>            : serve on address\n");
#ifdef MINIWEB_SSL_ENABLE
    fprintf(stderr, "-c <path>            : path to ssl cert pem\n");
    fprintf(stderr, "-k <path>            : path to private key pem\n");
#endif /* MINIWEB_SSL_ENABLE */
    fprintf(stderr, "-v                   : more verbose\n");
    fprintf(stderr, "-h                   : show help\n");
    fprintf(stderr, "----------------------------------------------\n");
    goto bail;
  } /* if */

#ifdef MINIWEB_SSL_ENABLE
  if (cert_path) {
    if (MINIWEB_ERR_OK != miniweb_ssl_init(&miniweb, server_addr, server_port,
         cert_path, key_path)) {
      fprintf(stderr, "SSL server init failed\n");
      goto bail;
    } /* if */
  } else
#endif
  if (MINIWEB_ERR_OK != miniweb_init(&miniweb, server_addr, server_port)) {
    fprintf(stderr, "server init failed\n");
    goto bail;
  } /* if */

  if (MINIWEB_ERR_OK != miniweb_register_handler(
      miniweb, miniweb_main_get_handler_cb, "GET", "/", NULL)) {
    fprintf(stderr, "root handler reg failed\n");
    goto cleanup;
  } /* if */

  if (MINIWEB_ERR_OK == miniweb_start(miniweb)) {
    /* wait for a signal */
    sem_wait(&miniweb_main_server_sem);
  } else {
    fprintf(stderr, "server start failed\n");
  } /* else */

cleanup:
  miniweb_fini(miniweb);

bail:
  return ret;
} /* main */
