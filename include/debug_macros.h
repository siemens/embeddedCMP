/* **************************************************************** */
/* Macros for Development */
/* TBD: Should be removed from library code. */
/* **************************************************************** */

#ifndef DEBUG_MACROS_H
#define DEBUG_MACROS_H
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MBED__
#define NEWLINE "\r\n"
#define SIZEFMT "%d"
#else
#define NEWLINE "\r\n"
#define SIZEFMT "%lu"
#endif

// #define EMBEDDEDCMP_DEBUG

#ifdef EMBEDDEDCMP_DEBUG
#define CMPDBGV(fmt, ...) \
    do { \
        PRINTF("DEBUG: %s:%d %s " fmt NEWLINE, __FILE__, __LINE__, __func__, \
               ##__VA_ARGS__); \
    } while (0);
#else
#define CMPDBGV(fmt, ...) /* no-op */
#endif

#define CMPDBGS(str) CMPDBGV(str)
#define CMPDBG       CMPDBGS("")

// TODO redirect to mbedtls_debug_print_msg or similar
#define PRINTF printf

#define CMP_MSG(prefix, fmt, ...) \
    do { \
        PRINTF(prefix "%s:%d %s(): " fmt, __FILE__, (int)__LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#define CMPWARNS(str) CMP_MSG("WARNING: ", "%s" NEWLINE, str);
#define CMPERRS(str) CMP_MSG("ERROR: ", "%s" NEWLINE, str);
#define CMPERRV_NL(fmt, ...) CMP_MSG("ERROR: ", fmt, ##__VA_ARGS__)
#define CMPERRV(fmt, ...) CMPERRV_NL(fmt NEWLINE, ##__VA_ARGS__)
#define CMPINFOV(fmt, ...) CMP_MSG("INFO: ", fmt NEWLINE, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* DEBUG_MACROS */
