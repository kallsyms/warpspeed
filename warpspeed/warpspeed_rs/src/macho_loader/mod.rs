use log::{debug, error, info, trace, warn};
use std::arch::asm;
use std::ffi::CStr;
use std::ffi::CString;

use hyperpom::applevisor as av;
use hyperpom::core::*;
use hyperpom::corpus::*;
use hyperpom::coverage::*;
use hyperpom::crash::*;
use hyperpom::error::*;
use hyperpom::loader::*;
use hyperpom::memory::*;
use hyperpom::tracer::*;
use hyperpom::utils::*;
use hyperpom::*;

use crate::macho_loader::loader_ffi::KERN_DENIED;
use crate::macho_loader::loader_ffi::KERN_NOT_FOUND;

mod loader_ffi;

// Empty global data.
#[derive(Clone)]
pub struct GlobalData;
// Empty local data.
#[derive(Clone)]
pub struct LocalData {
    pub shared_cache_base: u64,
}

#[derive(Clone)]
pub struct MachOLoader {
    executable: String,
    arguments: Vec<String>,

    entry_point: u64,
    stack_pointer: u64,
    tls: u64,
    shared_cache_base: u64,
}

impl MachOLoader {
    pub fn new(executable: &str, args: &Vec<String>) -> Result<Self> {
        // TODO: parse macho, check for arm64
        Ok(Self {
            executable: executable.to_string(),
            arguments: args.clone(),
            entry_point: 0,
            stack_pointer: 0,
            tls: 0,
            shared_cache_base: 0,
        })
    }

    fn pthread_hook(args: &mut hooks::HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        debug!("pthread token == 0 hook");
        args.vcpu
            .set_reg(av::Reg::PC, args.vcpu.get_reg(av::Reg::PC).unwrap() + 4)?;
        Ok(ExitKind::Continue)
    }

    fn objc_restartable_ranges_hook(
        args: &mut hooks::HookArgs<LocalData, GlobalData>,
    ) -> Result<ExitKind> {
        debug!("objc task_restartable_ranges_register hook");
        args.vcpu
            .set_reg(av::Reg::PC, args.ldata.shared_cache_base + 0x5e570)?;
        Ok(ExitKind::Continue)
    }
}

impl Loader for MachOLoader {
    type LD = LocalData;
    type GD = GlobalData;

    // Creates the mapping needed for the binary and writes the instructions into it.
    fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        let mut res: loader_ffi::load_results = unsafe { std::mem::zeroed() };

        {
            let argv_page = unsafe {
                nix::libc::mmap(
                    0 as *mut _,
                    0x10000,
                    nix::libc::PROT_READ | nix::libc::PROT_WRITE,
                    nix::libc::MAP_PRIVATE | nix::libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            trace!("argv_page = {:x}", argv_page as u64);
            executor
                .vma
                .map_1to1(argv_page as u64, 0x10000, av::MemPerms::RWX)?;
            let argv_ptrs: &mut [*const u8] =
                unsafe { std::slice::from_raw_parts_mut(argv_page as _, self.arguments.len()) };
            let mut argv_str: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(
                    argv_page.offset((std::mem::size_of::<u64>() * self.arguments.len()) as isize)
                        as _,
                    0x10000,
                )
            };
            for i in 0..self.arguments.len() {
                argv_ptrs[i] = argv_str.as_ptr();
                argv_str.copy_from_slice(self.arguments[i].as_bytes());
                argv_str = &mut argv_str[self.arguments[i].len() + 1..];
            }

            res.argc = self.arguments.len();
            res.argv = argv_page as _;
        }

        {
            let tls_page = unsafe {
                nix::libc::mmap(
                    0 as *mut _,
                    0x10000,
                    nix::libc::PROT_READ | nix::libc::PROT_WRITE,
                    nix::libc::MAP_PRIVATE | nix::libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            executor
                .vma
                .map_1to1(tls_page as u64, 0x10000, av::MemPerms::RWX)?;
            self.tls = tls_page as u64;
            trace!("tls_page = {:x}", tls_page as u64);
        }

        unsafe {
            let executable = CString::new(self.executable.as_bytes()).unwrap();
            loader_ffi::load(executable.as_ptr(), false, &mut res);
            loader_ffi::setup_stack64(executable.as_ptr(), &mut res);
            self.entry_point = res.entry_point;
            self.stack_pointer = res.stack_top;
            self.shared_cache_base = loader_ffi::map_shared_cache(&mut res) as u64;
            executor.ldata.shared_cache_base = self.shared_cache_base;
        }

        for m_i in 0..res.n_mappings {
            let mapping = res.mappings[m_i as usize];
            if mapping.hyper == mapping.guest_va {
                trace!(
                    "creating 1:1 mapping at {:x} size {:x}",
                    mapping.guest_va as u64,
                    mapping.len
                );
                executor.vma.map_1to1(
                    mapping.guest_va as u64,
                    round_virt_page!(mapping.len) as usize,
                    av::MemPerms::RWX,
                )?;
            } else {
                trace!(
                    "creating ** NON 1:1 ** mapping at {:x} size {:x}",
                    mapping.guest_va as u64,
                    mapping.len
                );
                executor.vma.map(
                    mapping.guest_va as u64,
                    round_virt_page!(mapping.len) as usize,
                    av::MemPerms::RWX,
                )?;
                executor.vma.write(mapping.guest_va as u64, unsafe {
                    std::slice::from_raw_parts(mapping.hyper as _, mapping.len)
                })?;
            }
        }

        trace!("map done");
        Ok(())
    }

    fn pre_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        debug!("Entry point: {:x}", self.entry_point);
        debug!("Stack pointer: {:x}", self.stack_pointer);
        debug!("TLS: {:x}", self.tls);
        executor.vcpu.set_reg(av::Reg::PC, self.entry_point)?;
        executor
            .vcpu
            .set_sys_reg(av::SysReg::SP_EL0, self.stack_pointer)?;
        executor
            .vcpu
            .set_sys_reg(av::SysReg::TPIDRRO_EL0, self.tls)?;
        Ok(ExitKind::Continue)
    }

    fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        // ghost: TODO: these are probably wrong now since upgrade
        executor.add_custom_hook(self.shared_cache_base + 0x3f9df8, MachOLoader::pthread_hook);
        executor.add_custom_hook(
            self.shared_cache_base + 0x5e554,
            MachOLoader::objc_restartable_ranges_hook,
        );
        Ok(())
    }

    // Unused
    fn load_testcase(
        &mut self,
        _executor: &mut Executor<Self, LocalData, GlobalData>,
        _testcase: &[u8],
    ) -> Result<LoadTestcaseAction> {
        Ok(LoadTestcaseAction::NewAndReset)
    }

    // Unused
    fn symbols(&self) -> Result<Symbols> {
        Ok(Symbols::new())
    }

    // Unused
    fn code_ranges(&self) -> Result<Vec<CodeRange>> {
        Ok(vec![])
    }

    // Unused
    fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
        Ok(vec![])
    }

    // Unused
    fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
        Ok(vec![])
    }

    fn exception_handler_sync_lowerel_aarch64(
        &self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        ldata: &mut Self::LD,
        _gdata: &std::sync::RwLock<Self::GD>,
    ) -> Result<ExitKind> {
        let elr = vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
        trace!("ELR_EL1: {:#x}", elr);
        let esr = vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;

        if esr != 0x56000080 {
            error!("Fault!");
            error!("{}", vcpu);
            return Ok(ExitKind::Crash("Unhandled fault".to_string()));
        }

        // This is our syscall handler
        let num = vcpu.get_reg(av::Reg::X16)?;
        let args: [u64; 16] = [
            vcpu.get_reg(av::Reg::X0)?,
            vcpu.get_reg(av::Reg::X1)?,
            vcpu.get_reg(av::Reg::X2)?,
            vcpu.get_reg(av::Reg::X3)?,
            vcpu.get_reg(av::Reg::X4)?,
            vcpu.get_reg(av::Reg::X5)?,
            vcpu.get_reg(av::Reg::X6)?,
            vcpu.get_reg(av::Reg::X7)?,
            vcpu.get_reg(av::Reg::X8)?,
            vcpu.get_reg(av::Reg::X9)?,
            vcpu.get_reg(av::Reg::X10)?,
            vcpu.get_reg(av::Reg::X11)?,
            vcpu.get_reg(av::Reg::X12)?,
            vcpu.get_reg(av::Reg::X13)?,
            vcpu.get_reg(av::Reg::X14)?,
            vcpu.get_reg(av::Reg::X15)?,
        ];

        let mut ret0: u64 = 0;
        let mut ret1: u64 = 0;
        let mut cflags: u64 = 0;

        let mut handled = false;
        match num {
            0x5 => {
                // open
                debug!("open({})", unsafe {
                    CStr::from_ptr(args[0] as _).to_string_lossy()
                });
            }
            0x10a => {
                // shm_open
                let name = unsafe { CStr::from_ptr(args[0] as _) };
                trace!("shm_open({})", name.to_string_lossy());
                if name.to_string_lossy() == "com.apple.featureflags.shm" {
                    debug!("Denying shm_open for featureflag");
                    ret0 = KERN_DENIED as _;
                    ret1 = 0;
                    cflags = 1 << 29;
                    handled = true;
                }
            }
            0x126 => {
                // shared_region_check_np
                // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/vm/vm_unix.c#L2017
                if args[0] != u64::MAX {
                    debug!(
                        "Returning {:x} for shared_region_check_np",
                        ldata.shared_cache_base
                    );
                    // *(uint64_t*)args[0] = shared_cache_base
                    unsafe {
                        *(args[0] as *mut u64) = ldata.shared_cache_base;
                    }
                }
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            0x150 => {
                // proc_info
                if args[0] == 0xf {
                    debug!("Stubbing out proc_info for PROC_INFO_CALL_SET_DYLD_IMAGES");
                    ret0 = 0;
                    ret1 = 0;
                    cflags = 0;
                    handled = true;
                }
            }
            0xffffffffffffffd1 => {
                // mach_msg2
                let flavor: u32 = unsafe { *((args[0] + 0x20) as *const u32) };
                // TODO: actually check for this being task_info
                if flavor == 0x11 {
                    debug!("Returning NOT_FOUND for TASK_DYLD_INFO");
                    ret0 = KERN_NOT_FOUND as _;
                    ret1 = 0;
                    cflags = 1 << 29;
                    handled = true;
                }
            }
            _ => {}
        }

        if !handled {
            debug!("Forwarding syscall {:x}(0x{:x?})", num, args);
            unsafe {
                asm!(
                    "svc #0x80",
                    "mov {ret0}, x0",
                    "mov {ret1}, x1",
                    "mrs {cflags}, NZCV",
                    in("x0") args[0],
                    in("x1") args[1],
                    in("x2") args[2],
                    in("x3") args[3],
                    in("x4") args[4],
                    in("x5") args[5],
                    in("x6") args[6],
                    in("x7") args[7],
                    in("x8") args[8],
                    in("x9") args[9],
                    in("x10") args[10],
                    in("x11") args[11],
                    in("x12") args[12],
                    in("x13") args[13],
                    in("x14") args[14],
                    in("x15") args[15],
                    in("x16") num,
                    ret0 = out(reg) ret0,
                    ret1 = out(reg) ret1,
                    cflags = out(reg) cflags,
                );
            }

            match num {
                0xc5 => {
                    // mmap
                    // applevisor (and therefore the round_phys_page macro) assumes 64k pages which isn't correct
                    let size = ((args[1] + (0x4000 - 1)) & !(0x4000 - 1)) as usize;
                    trace!("1:1 map of {:x} {:x} due to mmap", ret0, size);
                    vma.map_1to1(ret0, size, av::MemPerms::RWX)?;
                }
                0xfffffffffffffff6 => {
                    // mach_vm_allocate
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!(
                        "1:1 map of {:x} {:x} due to mach_vm_allocate",
                        addr,
                        args[2]
                    );
                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                }
                0xfffffffffffffff1 => {
                    // mach_vm_map
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!("1:1 map of {:x} {:x} due to mach_vm_map", addr, args[2]);
                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                }
                _ => {}
            }
        }

        debug!("Returning {:x} {:x} {:x}", ret0, ret1, cflags);
        vcpu.set_reg(av::Reg::X0, ret0)?;
        vcpu.set_reg(av::Reg::X1, ret1)?;

        // And jump back
        vcpu.set_reg(
            av::Reg::CPSR,
            (vcpu.get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28)) | cflags,
        )?;
        vcpu.set_reg(av::Reg::PC, elr)?;

        Ok(ExitKind::Continue)
    }
}
