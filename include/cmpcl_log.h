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

/* ---------------------------------------------------------------- */
/* Debug output function pointer type                               */
/* Like printf(), return the number of chars written, < 0 on error  */
/* ---------------------------------------------------------------- */
typedef int (*cmp_log_func_t)(const char *format, ...);

/**
 * @brief Sets the global logging output function.
 *
 * By default, output goes to printf(). Call this function to
 * redirect all CMP log macros to a custom handler (e.g., UART,
 * syslog, in-memory buffer, mbedtls_debug_print_msg wrapper, etc.)
 *
 * @param func  Pointer to a printf-compatible output function.
 *              Pass NULL to revert to the default (printf).
 */
 void cmp_set_log_function(cmp_log_func_t func);
 
 /**
 * @brief Returns the currently active logging function.
 *
 * Useful for temporarily saving and restoring the log handler.
 *
 * @return cmp_log_func_t  The currently registered output function.
 */
cmp_log_func_t cmp_get_log_function(void);
 
  
/**
 * @brief Silences all log output — nothing will be printed anywhere.
 *
 * Call cmp_set_log_function(NULL) to revert back to printf,
 * or cmp_set_log_function(previous) to restore a saved handler.
 */
void cmp_silence_log(void);

/* ---------------------------------------------------------------- */
/* Internal: active log function (do not call directly)            */
/* ---------------------------------------------------------------- */
cmp_log_func_t cmp_get_log_function(void);

/* ---------------------------------------------------------------- */
/* PRINTF shim — routes through the active log function            */
/* ---------------------------------------------------------------- */
#define PRINTF cmp_get_log_function()


 
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

#define CMPDBGS(str) CMPDBGV("%s", str)
#define CMPDBG       CMPDBGS("")

#define CMP_MSG(prefix, fmt, ...) \
    do { \
        PRINTF(prefix "%s:%d %s(): " fmt, __FILE__, (int)__LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#define CMPWARNV(fmt, ...) CMP_MSG("WARNING: ", fmt NEWLINE, ##__VA_ARGS__)
#define CMPWARNS(str) CMPWARNV("%s", str)
#define CMPERRS(str) CMP_MSG("ERROR: ", "%s" NEWLINE, str);
#define CMPERRV_NL(fmt, ...) CMP_MSG("ERROR: ", fmt, ##__VA_ARGS__)
#define CMPERRV(fmt, ...) CMPERRV_NL(fmt NEWLINE, ##__VA_ARGS__)
#define CMPINFOV(fmt, ...) CMP_MSG("INFO: ", fmt NEWLINE, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* DEBUG_MACROS */
