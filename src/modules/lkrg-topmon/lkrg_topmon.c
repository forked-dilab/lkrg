/*
 * File: lkrg/src/modules/lkrg-topmon/lkrg_topmon.c
 * Overview: Write LKRG alert data to shared memory and notify TEE using TOPMON SMC.
 * Functions:
 *   lkrg_topmon_init(): Map the shared-memory alert slot.
 *   lkrg_topmon_exit(): Release the shared-memory alert slot.
 *   lkrg_topmon_alert(): Publish an alert and trigger the SMC notification.
 */

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/string.h>
#include <linux/types.h>

#include "lkrg_topmon.h"
/* Exported by CONFIG_TOPMON_LKRG_ALERT in the Linux kernel. */
extern void smc_topmon_lkrg_alert(void);

/* Global Variables */
static struct lkrg_alert_info __iomem *topmon_alert_memory;
static atomic_t topmon_alert_sequence = ATOMIC_INIT(0);

/* Macros */
#define LKRG_TOPMON_LOG_PREFIX "[TOPMON][REE][LKRG][ALERT]: "
#define LKRG_TOPMON_USEC_PER_SEC 1000000ULL
#define LKRG_TOPMON_CENTISEC 100ULL
#define LKRG_TOPMON_HZ_PER_MHZ 1000000U

int lkrg_topmon_init(void)
{
    /* Variables */
    struct lkrg_alert_info __iomem *mapped_memory;
    size_t mapping_size;

    /* Assignments */
    mapped_memory = NULL;
    mapping_size = sizeof(struct lkrg_alert_info);

    /* Logic */
    if (topmon_alert_memory) {
        pr_info(LKRG_TOPMON_LOG_PREFIX
                "Shared-memory mapping already initialized.\n");
        return 0;
    }

    mapped_memory = ioremap(LKRG_TOPMON_ALERT_PHYS, mapping_size);
    if (!mapped_memory) {
        pr_err(LKRG_TOPMON_LOG_PREFIX
               "Shared-memory mapping failed: phys=0x%llx size=%zu\n",
               (unsigned long long)LKRG_TOPMON_ALERT_PHYS,
               mapping_size);
        return -ENOMEM;
    }

    topmon_alert_memory = mapped_memory;
    pr_info(LKRG_TOPMON_LOG_PREFIX
            "Shared-memory mapping initialized: phys=0x%llx size=%zu virt=%p\n",
            (unsigned long long)LKRG_TOPMON_ALERT_PHYS,
            mapping_size, mapped_memory);

    return 0;
}

void lkrg_topmon_exit(void)
{
    /* Variables */
    struct lkrg_alert_info __iomem *mapped_memory;

    /* Assignments */
    mapped_memory = topmon_alert_memory;

    /* Logic */
    if (!mapped_memory)
        return;

    /* Call only after all LKRG alert producers have been stopped. */
    topmon_alert_memory = NULL;
    iounmap(mapped_memory);
    pr_info(LKRG_TOPMON_LOG_PREFIX "Shared-memory mapping released.\n");
}

void lkrg_topmon_alert(u32 type, u64 addr, const char *msg,
                      u64 t0_alert_start_cntpct)
{
    /* Variables */
    struct lkrg_alert_info alert;
    struct lkrg_alert_info __iomem *shared_memory;
    u64 t1_notify_cntpct;
    u64 elapsed_counts;
    u64 elapsed_centimicroseconds;
    u64 elapsed_us;
    u64 elapsed_fraction;
    u32 timer_frequency_hz;

    /* Assignments */
    memset(&alert, 0, sizeof(alert));
    shared_memory = topmon_alert_memory;
    t1_notify_cntpct = 0;
    elapsed_counts = 0;
    elapsed_centimicroseconds = 0;
    elapsed_us = 0;
    elapsed_fraction = 0;
    timer_frequency_hz = 0;

    /* Logic */
    if (!shared_memory) {
        pr_err(LKRG_TOPMON_LOG_PREFIX "Alert dropped: shared memory not mapped.\n");
        return;
    }

    alert.magic = LKRG_TOPMON_ALERT_MAGIC;
    alert.sequence = (u32)atomic_inc_return(&topmon_alert_sequence);
    alert.attack_type = type;
    alert.target_addr = addr;
    alert.t0_alert_start_cntpct = t0_alert_start_cntpct;

    if (msg)
        strscpy(alert.message, msg, sizeof(alert.message));

    t1_notify_cntpct = lkrg_topmon_read_counter();
    timer_frequency_hz = lkrg_topmon_read_frequency_hz();
    alert.t1_notify_cntpct = t1_notify_cntpct;

    memcpy_toio(shared_memory, &alert, sizeof(alert));
    /* Ensure the TEE sees the payload before receiving the SMC notification. */
    wmb();
    smc_topmon_lkrg_alert();

    elapsed_counts = t1_notify_cntpct - t0_alert_start_cntpct;
    if (timer_frequency_hz != 0) {
        /* Quotient/remainder avoid overflow from multiplying raw counts. */
        elapsed_us = div64_u64(elapsed_counts, timer_frequency_hz) *
                     LKRG_TOPMON_USEC_PER_SEC;
        elapsed_centimicroseconds = div64_u64(
            (elapsed_counts % timer_frequency_hz) *
            (LKRG_TOPMON_USEC_PER_SEC * LKRG_TOPMON_CENTISEC),
            timer_frequency_hz);
        elapsed_us += elapsed_centimicroseconds / LKRG_TOPMON_CENTISEC;
        elapsed_fraction = elapsed_centimicroseconds % LKRG_TOPMON_CENTISEC;
        pr_info(LKRG_TOPMON_LOG_PREFIX
                "T0-T1: %llu.%02llu us(%llu count, %u MHz)\n",
                (unsigned long long)elapsed_us,
                (unsigned long long)elapsed_fraction,
                (unsigned long long)elapsed_counts,
                timer_frequency_hz / LKRG_TOPMON_HZ_PER_MHZ);
    }
}

/*
 * End of File: lkrg/src/modules/lkrg-topmon/lkrg_topmon.c
 */
