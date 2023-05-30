use std::ffi::CStr;
use std::ffi::CString;

use hyperpom::applevisor as av;
use hyperpom::config::*;
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

mod loader_ffi;

// Empty global data.
#[derive(Clone)]
pub struct GlobalData;
// Empty local data.
#[derive(Clone)]
pub struct LocalData;

#[derive(Clone)]
pub struct MachOLoader {
    executable: String,
    arguments: Vec<String>,

    entry_point: u64,
    stack_pointer: u64,
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
            shared_cache_base: 0,
        })
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
            executor
                .vma
                .map_1to1(argv_page as u64, 0x10000, av::MemPerms::RW)?;
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
                .map_1to1(tls_page as u64, 0x10000, av::MemPerms::RW)?;
        }

        unsafe {
            let executable = CString::new(self.executable.as_bytes()).unwrap();
            loader_ffi::load(executable.as_ptr(), false, &mut res);
            loader_ffi::setup_stack64(executable.as_ptr(), &mut res);
            self.entry_point = res.entry_point;
            self.stack_pointer = res.stack_top;
            self.shared_cache_base = loader_ffi::map_shared_cache(&mut res) as u64;
        }

        for m_i in 0..res.n_mappings {
            let mapping = res.mappings[m_i as usize];
            executor.vma.map_1to1(
                mapping.hyper as u64,
                round_virt_page!(mapping.len) as usize,
                av::MemPerms::RWX,
            )?;
        }

        Ok(())
    }

    // Sets PC to the entry point.
    fn pre_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        executor.vcpu.set_reg(av::Reg::PC, self.entry_point)?;
        executor
            .vcpu
            .set_sys_reg(av::SysReg::SP_EL0, self.stack_pointer)?;
        Ok(ExitKind::Continue)
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
}
