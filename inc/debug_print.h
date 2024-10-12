#include <stdio.h>
#include <stdbool.h>

#ifndef DEBUG_PRINT_H
#define DEBUG_PRINT_H 1

#ifdef ENABLE_DEBUG_PRINTS

typedef struct {
  int level;
  FILE *fp;
} debug_print_t;

extern debug_print_t debug_print;

#define TRACE_PRINTF(fmt, ...) \
     if (debug_print.level > 3) \
       fprintf(debug_print.fp, \
         "%s:%s:%d:"fmt,  __FILE__, __FUNCTION__, __LINE__ \
         ,##__VA_ARGS__)
#define DEBUG_PRINTF(fmt, ...) \
     if (debug_print.level > 2) \
       fprintf(debug_print.fp, \
         "%s:%s:%d:"fmt,  __FILE__, __FUNCTION__, __LINE__ \
         ,##__VA_ARGS__)
#define DEBUG_PRINT_HEX(addr, len) \
     if (debug_print.level > 2) { \
       const unsigned char *dph_addr = addr; \
       int dph_remaining = len; \
       int dph_off = 0; \
       int dph_col = 0; \
       while(dph_remaining) { \
         if (dph_col == 0) \
           fprintf(debug_print.fp, "%s:%s:%d:%04x:%02x",\
             __FILE__, __FUNCTION__, __LINE__, dph_off, *dph_addr); \
         else \
           fprintf(debug_print.fp, " %02x", *dph_addr);\
         if (8 == ++dph_col) { \
           fprintf(debug_print.fp, "\n"); \
           dph_col = 0;\
         } /* if */ \
         dph_addr++; \
         dph_off++; \
         dph_remaining--; \
       } /* while */ \
       if (dph_col) \
         fprintf(debug_print.fp, "\n"); \
     } /* if */
#define INFO_PRINTF(fmt, ...) \
     if (debug_print.level > 1) \
       fprintf(debug_print.fp, \
          "%s:%s:%d:"fmt,  __FILE__, __FUNCTION__, __LINE__ \
         ,##__VA_ARGS__)
#define WARNING_PRINTF(fmt, ...) \
     if (debug_print.level > 0) \
       fprintf(debug_print.fp, \
         "%s:%s:%d:"fmt,  __FILE__, __FUNCTION__, __LINE__ \
         ,##__VA_ARGS__)
#define ERROR_PRINTF(fmt, ...) \
     fprintf(debug_print.fp, \
        "%s:%s:%d:"fmt,  __FILE__, __FUNCTION__, __LINE__ \
        ,##__VA_ARGS__)
#define ASSERT_PRINTF(cond, fmt, ...) \
     if (!cond) \
       fprintf(debug_print.fp, \
         "%s:%s:%d:"#cond":"fmt,  __FILE__, __FUNCTION__, __LINE__ \
         ,##__VA_ARGS__)
#define ASSERT_ABORT(cond) \
     if (!cond) \
       do { fprintf(debug_print.fp, \
         "%s:%s:%d:"#cond,  __FILE__, __FUNCTION__, __LINE__ ); \
         abort(); } while(false)
#else
#define TRACE_PRINTF(...) do {} while(false)
#define DEBUG_PRINTF(...) do {} while(false)
#define DEBUG_PRINT_HEX(...) do {} while(false)
#define INFO_PRINTF(...) do {} while(false)
#define WARNING_PRINTF(...) do {} while(false)
#define ERROR_PRINTF(...) do {} while(false)
#define ASSERT_PRINTF(cond, fmt, ...) \
    do { \
      ((void)(true ? 0 : ((cond), void(), 0))); \
    } while(false)
#define ASSERT_ABORT(cond) \
    do { \
      ((void)(true ? 0 : ((cond), void(), 0))); \
    } while(false)
#endif

#endif /* DEBUG_PRINT_H */
