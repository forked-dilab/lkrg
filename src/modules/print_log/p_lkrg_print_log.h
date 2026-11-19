/*
 * File: lkrg/src/modules/print_log/p_lkrg_print_log.h
 * Overview: LKRG logging macros and TOPMON alert forwarding.
 * Functions:
 *   p_print_log(): Format LKRG logs and forward alert-level events.
 *   p_panic(): Report a fatal alert and panic.
 */

/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Logging and debugging module
 *
 * Notes:
 *  - Debugging settings, error code definitions, and logging macros
 *
 * Timeline:
 *  - Created: 24.XI.2015
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PRINT_LOG_H
#define P_LKRG_PRINT_LOG_H

#include "../lkrg-topmon/lkrg_topmon.h"

/*
 * Include the header that defines ATTACK_TYPE_EXPLOIT,
 * ATTACK_TYPE_INTEGRITY, and struct lkrg_alert_info.
 *
 * Update the prototype to match the new definition in lkrg_topmon.c.
 * It now accepts attack type, address, and a message string.
 */
extern void lkrg_topmon_alert(uint32_t type, uint64_t addr,
                                const char *msg, uint64_t t0_alert_start_cntpct);

#include "../net/net.h"

/*
 * Debugging settings
 */

// Do we want to provide debug information?
#define P_LKRG_DEBUG

/* Do we want to precisely track changes of 'off' flag per each process?
 * If yes, uncomment it here */
//#define P_LKRG_TASK_OFF_DEBUG

// Do we want to precisely track all kernel .text section changes?
// By default NO. If you want it (and print relevant information)
// Uncomment it here
//#define P_LKRG_JUMP_LABEL_STEXT_DEBUG

// Debug every time we enter/exit notifiers function?
// not recommended - will be too noisy for some notifiers! :)
//#define P_LKRG_NOTIFIER_DBG


/*
 * Error codes
 */

// Everything is fine...
#define P_LKRG_SUCCESS                        0

// General error
#define P_LKRG_GENERAL_ERROR                  -1

// Can't find (resolve) "kallsyms_lookup_name" function
#define P_LKRG_RESOLVER_ERROR                 -100

// Can't initialize kmod module
#define P_LKRG_KMOD_ERROR                     -101

// Can't generate database - hashes
#define P_LKRG_DATABASE_ERROR                 -102

// Can't initialize protected features
#define P_LKRG_PROTECTED_FEATURES_ERROR       -103

// Can't register hot CPU plug[in/out] handler
#define P_LKRG_HPCPU_ERROR                    -104

// Can't register hot CPU plug[in/out] handler
#define P_LKRG_EXPLOIT_DETECTION_ERROR        -105

// User disabled loading LKRG from boot parameters
#define P_LKRG_BOOT_DISABLE_LKRG              -125

// Enable hash from IOMMU table? - not recommended!
// By default disabled
//#define P_LKRG_IOMMU_HASH_ENABLED

#define P_LKRG_KMOD_DUMP_RACE                 -200


/*
 * Logging macros
 */

// Signature in logs...
#define P_LKRG_SIGNATURE "LKRG: "

#define P_LOG_MIN   0
#define P_LOG_ALERT 0
#define P_LOG_ALIVE 1
#define P_LOG_FAULT 2
#define P_LOG_ISSUE 3
#define P_LOG_WATCH 4
#define P_LOG_DEBUG 5
#define P_LOG_FLOOD 6
#define P_LOG_MAX   6

#define P_LOG_STATE (0x10 | P_LOG_ALIVE)
#define P_LOG_DYING (0x20 | P_LOG_ALIVE)
#define P_LOG_FATAL (0x30 | P_LOG_FAULT)

#define p_print_log(p_level, p_fmt, p_args...)                                             \
({                                                                                         \
   int p_print_ret = 0;                                                                    \
   uint64_t t0_alert_start_cntpct;                                                          \
                                                                                           \
   /* Trigger for WATCH and ALERT to notify TOPPERS (TEE) via Shared Memory */             \
   /* if ((p_level) == P_LOG_ALERT || (p_level) == P_LOG_WATCH) { */                       \
   t0_alert_start_cntpct = 0;                                                            \
   if ((p_level) == P_LOG_ALERT) {                                                         \
       uint32_t p_alert_type = ATTACK_TYPE_EXPLOIT;                                       \
       t0_alert_start_cntpct = lkrg_topmon_read_counter();                                \
                                                                                           \
       /* 1. Format the message for the shared memory buffer */                             \
       char p_buf[128];                                                                     \
       snprintf(p_buf, sizeof(p_buf), p_fmt, ## p_args);                                    \
                                                                                           \
       /* 2. Send the detailed alert to TOPPERS/FMP3 */                                     \
       /* target_addr is set to 0 here; specific addresses can be hooked in checkers */     \
       lkrg_topmon_alert(p_alert_type, 0, p_buf, t0_alert_start_cntpct);                 \
   }                                                                                       \
                                                                                           \
   if ((p_level) == P_LOG_ALERT) {                                                         \
      p_print_ret = printk(KERN_CRIT    P_LKRG_SIGNATURE "ALERT: " p_fmt "\n", ## p_args); \
   } else if (P_CTRL(p_log_level) >= ((p_level) & 7))                                      \
   switch (p_level) {                                                                      \
   default: /* Pacify clang warning about no case P_LOG_ALERT, which we handle above */    \
      break;                                                                               \
   case P_LOG_ALIVE:                                                                       \
      p_print_ret = printk(KERN_NOTICE  P_LKRG_SIGNATURE "ALIVE: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_STATE:                                                                       \
      p_print_ret = printk(KERN_NOTICE  P_LKRG_SIGNATURE "STATE: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_DYING:                                                                       \
      p_print_ret = printk(KERN_NOTICE  P_LKRG_SIGNATURE "DYING: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_FAULT:                                                                       \
      p_print_ret = printk(KERN_ERR     P_LKRG_SIGNATURE "FAULT: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_FATAL:                                                                       \
      p_print_ret = printk(KERN_ERR     P_LKRG_SIGNATURE "FATAL: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_ISSUE:                                                                       \
      p_print_ret = printk(KERN_WARNING P_LKRG_SIGNATURE "ISSUE: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_WATCH:                                                                       \
      p_print_ret = printk(KERN_INFO    P_LKRG_SIGNATURE "WATCH: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_DEBUG:                                                                       \
      p_print_ret = printk(KERN_DEBUG   P_LKRG_SIGNATURE "DEBUG: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   case P_LOG_FLOOD:                                                                       \
      p_print_ret = printk(KERN_DEBUG   P_LKRG_SIGNATURE "FLOOD: " p_fmt "\n", ## p_args); \
      break;                                                                               \
   }                                                                                       \
                                                                                           \
   lkrg_queue_net();                                                                       \
                                                                                           \
   p_print_ret;                                                                            \
})

#define p_panic(p_fmt, p_args...) \
({ \
   p_print_log(P_LOG_ALERT, "BLOCK: " p_fmt, ## p_args); \
   panic(p_fmt, ## p_args); \
})

#ifdef P_LKRG_DEBUG

#ifdef P_LKRG_NOTIFIER_DBG
 #define p_debug_notifier_log(p_fmt, p_args...)                                          \
                  p_debug_log(P_LOG_FLOOD, p_fmt, ## p_args)
#else
 #define p_debug_notifier_log(p_fmt, p_args...)  ({ 0; })
#endif

#ifdef P_LKRG_STRONG_KPROBE_DEBUG
 #define p_debug_kprobe_log(p_fmt, p_args...)                                            \
                  p_debug_log(P_LOG_FLOOD, p_fmt, ## p_args)
#else
 #define p_debug_kprobe_log(p_fmt, p_args...)    ({ 0; })
#endif

#define p_debug_log p_print_log

#else

#define p_debug_log(p_level, p_fmt, p_args...)  ({ 0; })

#define p_debug_notifier_log(p_fmt, p_args...)  ({ 0; })
#define p_debug_kprobe_log(p_fmt, p_args...)    ({ 0; })

#endif

#endif

/*
 * End of File: lkrg/src/modules/print_log/p_lkrg_print_log.h
 */
