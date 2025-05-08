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

// #define DEBUG

#ifdef DEBUG
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

#define CMPWARNS(str) \
    do { \
        PRINTF("WARNING: %s:%d %s " str NEWLINE, __FILE__, (int) __LINE__, __func__); \
    } while (0)
#define CMPERRS(str)                            \
    do { \
        PRINTF("ERROR: %s:%d %s " str NEWLINE, __FILE__, (int) __LINE__, __func__); \
    } while (0)

#define CMPERRV(fmt, ...) \
    do { \
        PRINTF("ERROR: %s:%d %s " fmt NEWLINE, __FILE__, (int) __LINE__, __func__, \
               ##__VA_ARGS__); \
    } while (0)

#define CMPINFOV(fmt, ...) \
    do { \
        PRINTF("INFO: " fmt NEWLINE, ##__VA_ARGS__); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* DEBUG_MACROS */
