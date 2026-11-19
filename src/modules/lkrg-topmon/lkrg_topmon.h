/*
 * File: lkrg/src/modules/lkrg-topmon/lkrg_topmon.h
 * Overview: Define LKRG alert shared-memory ABI and TOPMON alert API.
 * Functions:
 *   lkrg_topmon_read_counter(): Read the physical ARM Generic Timer counter.
 *   lkrg_topmon_read_frequency_hz(): Read the ARM Generic Timer frequency.
 *   lkrg_topmon_init(): Map the TOPMON alert shared-memory region.
 *   lkrg_topmon_exit(): Release the TOPMON alert shared-memory region.
 *   lkrg_topmon_alert(): Publish an LKRG alert and notify the TEE.
 */

#ifndef LKRG_TOPMON_H
#define LKRG_TOPMON_H

#include <linux/types.h>
#include <asm/sysreg.h>

/* Shared-memory layout must match the current TOPPERS/FMP3 header. */
#define LKRG_TOPMON_SHM_BASE          0xBF000000ULL
#define LKRG_TOPMON_ALERT_OFFSET      0x00000000ULL
#define LKRG_TOPMON_ALERT_PHYS        (LKRG_TOPMON_SHM_BASE + LKRG_TOPMON_ALERT_OFFSET)
#define LKRG_TOPMON_ALERT_MAGIC       0x414C5254U
#define LKRG_TOPMON_MESSAGE_SIZE      128U
#define ATTACK_TYPE_INTEGRITY         1U
#define ATTACK_TYPE_EXPLOIT           2U

struct lkrg_alert_info {
    u32 magic;
    u32 sequence;
    u32 attack_type;
    u32 reserved;
    u64 target_addr;
    u64 t0_alert_start_cntpct;
    u64 t1_notify_cntpct;
    char message[LKRG_TOPMON_MESSAGE_SIZE];
};

static inline u64 lkrg_topmon_read_counter(void)
{
    /* Logic */
    return read_sysreg(cntpct_el0);
}

static inline u32 lkrg_topmon_read_frequency_hz(void)
{
    /* Logic */
    return (u32)read_sysreg(cntfrq_el0);
}

int lkrg_topmon_init(void);
void lkrg_topmon_exit(void);
void lkrg_topmon_alert(u32 type, u64 addr, const char *msg,
                      u64 t0_alert_start_cntpct);

#endif /* LKRG_TOPMON_H */

/*
 * End of File: lkrg/src/modules/lkrg-topmon/lkrg_topmon.h
 */
