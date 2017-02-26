extern crate goblin;
extern crate colored;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;

use goblin::{error, Hint, pe, elf, mach, archive};
use std::path::Path;
use std::fs::File;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "bg", about = "bingrep - grepping through binaries since 2017")]
struct Opt {
    /// A flag, true if used in the command line.
    #[structopt(short = "d", long = "debug", help = "Print debug version of parse results")]
    debug: bool,

    /// Needed parameter, the first on the command line.
    #[structopt(help = "Binary file")]
    input: String,
}

struct Elf {
    elf: elf::Elf,
}

impl ::std::fmt::Display for Elf {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        use elf::header;
        use elf::program_header;
        use elf::section_header;
        use elf::sym;
        use elf::dyn;
        use elf::Dynamic;
        use elf::Syms;
        use elf::strtab::Strtab;
        use elf::reloc::{self, Reloc};
        use colored::*;

        let hdr = |name: &str| {
            format!("{}", name).dimmed().white().underline()
        };
        let hdr_size = |name: &str, size| {
            format!("{}({})", name, size).dimmed().white().underline()
        };

        let fmt_header = |fmt: &mut ::std::fmt::Formatter, name: &str, size: usize| -> ::std::fmt::Result {
            writeln!(fmt, "{}:\n", hdr_size(name, size))?;
            Ok(())
        };
        let addr = |addr| {
            format!("{:x}",addr).red()
        };
        let addrx = |addr| {
            format!("{:#x}",addr).red()
        };
        let off = |off| {
            format!("{:#x}",off).yellow()
        };
        let offs = |off: isize| {
            format!("{:#x}",off).yellow()
        };
        let string = |s: &str| {
            s.hidden().bold().yellow()
        };
        let sz = |sz| {
            format!("{:#x}", sz).green()
        };

        let header = &self.elf.header;
        let endianness = if self.elf.little_endian { "little-endian" } else { "big-endian" };
        let kind = {
            let typ = header.e_type;
            let kind_str = header::et_to_str(typ).hidden().bold();
            match typ {
                header::ET_REL =>  kind_str.yellow(),
                header::ET_EXEC => kind_str.red(),
                header::ET_DYN =>  kind_str.blue(),
                header::ET_CORE => kind_str.black(),
                _ => kind_str.normal(),
            }
        };
        let machine = header.e_machine;
        let machine_str = {
            header::machine_to_str(machine).bold()
        };
        writeln!(fmt, "{} {} {}-{} @ {}:",
                 hdr("ELF"),
                 kind,
                 machine_str,
                 endianness,
                 addrx(self.elf.entry as u64),
        )?;
        writeln!(fmt, "")?;
        writeln!(fmt, "e_phoff: {} e_shoff: {} e_flags: {:#x} e_ehsize: {} e_phentsize: {} e_phnum: {} e_shentsize: {} e_shnum: {} e_shstrndx: {}",
                 off(header.e_phoff),
                 off(header.e_shoff),
                 header.e_flags,
                 header.e_ehsize,
                 header.e_phentsize,
                 header.e_phnum,
                 header.e_shentsize,
                 header.e_shnum,
                 header.e_shstrndx,
        )?;
        writeln!(fmt, "")?;

        fmt_header(fmt, "ProgramHeaders", self.elf.program_headers.len())?;
        let mut i = true;
        for phdr in &self.elf.program_headers {
            let name = {
                let typ = phdr.p_type;
                let name = format!("{:.16}", program_header::pt_to_str(typ));
                let name = if i { name.on_yellow() } else { name.normal() };
                match typ {
                    program_header::PT_LOAD    => name.red(),
                    program_header::PT_INTERP  => name.yellow(),
                    program_header::PT_DYNAMIC => name.cyan(),
                    _ => name
                }
            };
            let flags = {
                let wx = program_header::PF_W|program_header::PF_X;
                let rx = program_header::PF_R|program_header::PF_X;
                let rwx = program_header::PF_R|program_header::PF_W|program_header::PF_X;
                let rw = program_header::PF_R|program_header::PF_W;
                let flags = phdr.p_flags;
                if flags == rwx { "RW+X" }
                else if flags == rw { "RW" }
                else if flags == rx { "R+X" }
                else if flags == wx { "W+X" }
                else if flags == program_header::PF_R { "R" }
                else if flags == program_header::PF_W { "W" }
                else if flags == program_header::PF_R { "R" }
                else { "BAD" }
            };
            write!(fmt, "{:<16} ", name)?;
            write!(fmt, "{:>4} ", flags)?;
            write!(fmt, "p_offset: {:<16} ", off(phdr.p_offset))?;
            write!(fmt, "p_vaddr: {:<16} ", addrx(phdr.p_vaddr))?;
            write!(fmt, "p_paddr: {:<16} ", addrx(phdr.p_paddr).bold())?;
            write!(fmt, "p_filesz: {:<16} ", sz(phdr.p_filesz))?;
            write!(fmt, "p_memsz: {:<16} ", sz(phdr.p_memsz).bold())?;
            write!(fmt, "p_flags: {:#x} ", phdr.p_flags)?;
            writeln!(fmt, "p_align: {:#x}", phdr.p_align)?;
            i = !i;
        }
        writeln!(fmt, "")?;

        fmt_header(fmt, "SectionHeaders", self.elf.section_headers.len())?;
        let shdr_strtab = &self.elf.shdr_strtab;
        let mut i = true;
        for shdr in &self.elf.section_headers {
            let name = {
                let name = format!("{:.16}", &shdr_strtab[shdr.sh_name]);
                if i { name.hidden() } else { name.normal() }
            };
            write!(fmt, "{:<16} ", name)?;
            write!(fmt, "{} ", section_header::sht_to_str(shdr.sh_type))?;
            write!(fmt, "sh_offset: {} ", off(shdr.sh_offset))?;
            write!(fmt, "sh_addr: {} ", addrx(shdr.sh_addr))?;
            write!(fmt, "sh_size: {} ", sz(shdr.sh_size))?;
            write!(fmt, "sh_link: {} "   , shdr.sh_link)?;
            write!(fmt, "sh_info: {:#x} ", shdr.sh_info)?;
            write!(fmt, "sh_entsize: {:#x} ", shdr.sh_entsize)?;
            write!(fmt, "sh_flags: {:#x} ", shdr.sh_flags)?;
            writeln!(fmt, "sh_addralign: {:#x}", shdr.sh_addralign)?;
            i = !i;
        }
        writeln!(fmt, "")?;

        let fmt_syms = |fmt: &mut ::std::fmt::Formatter, name: &str, syms: &Syms, strtab: &Strtab | -> ::std::fmt::Result {
            fmt_header(fmt, name, syms.len())?;
            for sym in syms {
                let bind = {
                    let bind_str = format!("{:.8}", sym::bind_to_str(sym.st_bind())).hidden().bold();
                    match sym.st_bind() {
                        sym::STB_LOCAL => bind_str.cyan(),
                        sym::STB_GLOBAL => bind_str.red(),
                        sym::STB_WEAK => bind_str.magenta(),
                        _ => bind_str.normal().clear(),
                    }
                };
                let typ = {
                    let typ_str = format!("{:.9}", sym::type_to_str(sym.st_type())).bold();
                    match sym.st_type() {
                        sym::STT_OBJECT => typ_str.yellow(),
                        sym::STT_FUNC => typ_str.red(),
                        sym::STT_GNU_IFUNC => typ_str.cyan(),
                        _ => typ_str.clear(),
                    }
                };
                write!(fmt, "{:>16} ", addr(sym.st_value))?;
                write!(fmt, "{:<8} {:<9} ", bind, typ)?;
                write!(fmt, "{} ", string(&strtab[sym.st_name]))?;
                write!(fmt, "st_size: {} ",  sz(sym.st_size))?;
                write!(fmt, "st_other: {:#x} ", sym.st_other)?;
                writeln!(fmt, "st_shndx: {:#x}",sym.st_shndx)?;
            }
            writeln!(fmt, "")?;
            Ok(())
        };

        let dyn_strtab = &self.elf.dynstrtab;
        let strtab = &self.elf.strtab;
        fmt_syms(fmt, "Dyn Syms", &self.elf.dynsyms, dyn_strtab)?;
        fmt_syms(fmt, "Syms", &self.elf.syms, strtab)?;

        if let &Some(Dynamic { ref dyns, .. }) = &self.elf.dynamic {
            fmt_header(fmt, "Dynamic", dyns.len())?;
            for dyn in dyns {
                let tag = dyn.d_tag;
                let val = dyn.d_val;
                let tag_str = dyn::tag_to_str(tag).cyan();
                write!(fmt, "{:>16} ", tag_str)?;
                match tag {
                    dyn::DT_NEEDED => writeln!(fmt, "{}", string(&dyn_strtab[val as usize]))?,
                    dyn::DT_INIT => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_FINI => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_INIT_ARRAY => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_INIT_ARRAYSZ => writeln!(fmt, "{}", sz(val))?,
                    dyn::DT_FINI_ARRAY => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_FINI_ARRAYSZ => writeln!(fmt, "{}", sz(val))?,
                    dyn::DT_GNU_HASH => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_STRTAB => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_SYMTAB => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_STRSZ => writeln!(fmt, "{}", sz(val))?,
                    dyn::DT_PLTGOT => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_PLTRELSZ => writeln!(fmt, "{}", sz(val))?,
                    dyn::DT_JMPREL => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_RELA => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_RELASZ => writeln!(fmt, "{}", sz(val))?,
                    dyn::DT_VERNEED => writeln!(fmt, "{}", addrx(val))?,
                    dyn::DT_VERSYM => writeln!(fmt, "{}", addrx(val))?,
                    _ => writeln!(fmt, "{:#x}", dyn.d_val)?,
                }
            }
        } else {
            writeln!(fmt, "{}: None", hdr("Dynamic"))?;
        }
        writeln!(fmt, "")?;

        let fmt_relocs = |fmt: &mut ::std::fmt::Formatter, relocs: &[Reloc], syms: &Syms, strtab: &Strtab | -> ::std::fmt::Result {
            for reloc in relocs {
                let sym = &syms[reloc.r_sym];
                write!(fmt, "{:>16} ", addr(reloc.r_offset as u64))?;
                let name = if sym.st_name == 0 { "ABS".dimmed() } else { string(&strtab[sym.st_name]) };
                write!(fmt, "{} ",  reloc::r_to_str(reloc.r_type, machine))?;
                writeln!(fmt, "{}+{}", name, offs(reloc.r_addend))?;
            }
            writeln!(fmt, "")?;
            Ok(())
        };

        fmt_header(fmt, "Dynamic Relocations", self.elf.dynsyms.len())?;
        fmt_relocs(fmt,  &self.elf.dynrelas, &self.elf.dynsyms, &dyn_strtab)?;
        fmt_header(fmt, "Plt Relocations", self.elf.dynsyms.len())?;
        fmt_relocs(fmt, &self.elf.pltrelocs, &self.elf.dynsyms, &dyn_strtab)?;

        let num_shdr_relocs = self.elf.shdr_relocs.len();
        fmt_header(fmt, "Shdr Relocations", num_shdr_relocs)?;
        if num_shdr_relocs != 0 {
            let mut i = 0;
            for shdr in &self.elf.section_headers {
                if shdr.sh_type == section_header::SHT_REL || shdr.sh_type == section_header::SHT_RELA {
                    let size = (shdr.sh_size / shdr.sh_entsize) as usize;
                    let shdr = &self.elf.section_headers[shdr.sh_info as usize];
                    let name = &shdr_strtab[shdr.sh_name];
                    writeln!(fmt, "  {}({})", name.bold(), size)?;
                    fmt_relocs(fmt, &self.elf.shdr_relocs.as_slice()[i..i+size], &self.elf.syms, &strtab)?;
                    i += size;
                }
            }
        }

        fmt_header(fmt, "Libraries", self.elf.libraries.len())?;
        for lib in &self.elf.libraries {
            writeln!(fmt, "{:>16} ", string(lib).blue())?;
        }
        writeln!(fmt, "")?;

        writeln!(fmt, "Soname: {:?}", self.elf.soname)?;
        writeln!(fmt, "Interpreter: {}", if let &Some(ref interpreter) = &self.elf.interpreter{ interpreter.to_owned() } else { "None".to_string() })?;
        writeln!(fmt, "is_64: {}", self.elf.is_64)?;
        writeln!(fmt, "is_lib: {}", self.elf.is_lib)?;
        writeln!(fmt, "little_endian: {}", self.elf.little_endian)?;
        writeln!(fmt, "bias: {:#x}", self.elf.bias)?;
        writeln!(fmt, "entry: {}", addr(self.elf.entry as u64))?;

        Ok(())
    }
}

fn run (opt: Opt) -> error::Result<()> {
    let path = Path::new(&opt.input);
    let mut fd = File::open(path)?;
    match goblin::peek(&mut fd)? {
        Hint::Elf(_) => {
            let elf = elf::Elf::try_from(&mut fd)?;
            if opt.debug {
                println!("{:#?}", elf);
            } else {
                println!("{}", Elf {elf: elf});
            }
        },
        Hint::PE => {
            let pe = pe::PE::try_from(&mut fd)?;
            println!("pe: {:#?}", &pe);
        },
        // wip
        Hint::Mach => {
            let mach = mach::Mach::try_from(&mut fd)?;
            println!("mach: {:#?}", &mach);
        },
        Hint::Archive => {
            let archive = archive::Archive::try_from(&mut fd)?;
            println!("archive: {:#?}", &archive);
        },
        Hint::Unknown(magic) => {
            println!("unknown magic: {:#x}", magic)
        }
    }
    Ok(())
}

pub fn main () {
    let opt = Opt::from_args();
    match run(opt) {
        Ok(()) => (),
        Err(err) => println!("{:#}", err)
    }
}
