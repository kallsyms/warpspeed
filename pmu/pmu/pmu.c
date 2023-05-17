#include <sys/systm.h>
#include <mach/mach_types.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <sys/proc.h>

#define PMC2 "s3_2_c15_c2_0"
#define PMC3 "s3_2_c15_c3_0"
#define PMC4 "s3_2_c15_c4_0"
#define PMC5 "s3_2_c15_c5_0"
#define PMC6 "s3_2_c15_c6_0"
#define PMC7 "s3_2_c15_c7_0"
#define PMC8 "s3_2_c15_c9_0"
#define PMC9 "s3_2_c15_c10_0"

#define PMU_IOCTL_SET_COUNT 1
typedef struct pmu_ioctl_set_count_args
{
  uint8_t pmc;
  uint64_t count;
} pmu_ioctl_set_count_args;

pid_t pid = -1;

static int dev_open(dev_t dev, int oflags, int devtype, struct proc *p)
{
  if (pid != -1)
  {
    return EBUSY;
  }
  pid = proc_pid(p);
  return 0;
}

static int dev_close(dev_t dev, int flag, int fmt, struct proc *p)
{
  pid = -1;
  return 0;
}

#define CASE_PMC(pmc)                                                                    \
  case pmc:                                                                              \
    __asm__ __volatile__("msr s3_2_c15_c" #pmc "_0, %0" ::"r"((1 << 48) - args->count)); \
    break;

static int dev_ioctl(
    dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
  switch (cmd)
  {
  case PMU_IOCTL_SET_COUNT:
  {
    pmu_ioctl_set_count_args *args = (pmu_ioctl_set_count_args *)data;

    switch (args->pmc)
    {
      CASE_PMC(2)
      CASE_PMC(3)
      CASE_PMC(4)
      CASE_PMC(5)
      CASE_PMC(6)
      CASE_PMC(7)
    default:
      return EINVAL;
    }
  }
  default:
    return EINVAL;
  }
}

static struct cdevsw cdevsw = {
    dev_open,   // open_close_fcn_t *d_open;
    dev_close,  // open_close_fcn_t *d_close;
    eno_rdwrt,  // read_write_fcn_t *d_read;
    eno_rdwrt,  // read_write_fcn_t *d_write;
    dev_ioctl,  // ioctl_fcn_t      *d_ioctl;
    eno_stop,   // stop_fcn_t       *d_stop;
    eno_reset,  // reset_fcn_t      *d_reset;
    NULL,       // struct tty      **d_ttys;
    eno_select, // select_fcn_t     *d_select;
    eno_mmap,   // mmap_fcn_t       *d_mmap;
    eno_strat,  // strategy_fcn_t   *d_strategy;
    eno_getc,   // getc_fcn_t       *d_getc;
    eno_putc,   // putc_fcn_t       *d_putc;
    0           // int               d_type;
};

int major_number = -1;
void *devfs = NULL;

kern_return_t pmu_start(kmod_info_t *ki, void *d)
{
  kprintf("Starting PMU kext");

  major_number = cdevsw_add(-1, &cdevsw);
  if (major_number < 0)
  {
    kprintf("Could not get a major number!\n");
    goto fail;
  }

  devfs = devfs_make_node(makedev(major_number, 0),
                          DEVFS_CHAR,
                          UID_ROOT,
                          GID_WHEEL,
                          0600,
                          "mrr_pmu",
                          0);
  if (devfs == NULL)
  {
    kprintf("Could not get a devfs entry!\n");
    goto fail;
  }

  return KERN_SUCCESS;

  // keep up the apple tradition
fail:
  if (devfs != NULL)
  {
    devfs_remove(devfs);
    devfs = NULL;
  }

  if (major_number >= 0)
  {
    cdevsw_remove(major_number, &cdevsw);
  }

  return KERN_FAILURE;
}

kern_return_t pmu_stop(kmod_info_t *ki, void *d)
{
  if (pid != -1)
  {
    return KERN_FAILURE;
  }

  devfs_remove(devfs);
  cdevsw_remove(major_number, &cdevsw);

  return KERN_SUCCESS;
}
