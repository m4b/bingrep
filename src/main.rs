extern crate goblin;
extern crate colored;
extern crate structopt;
extern crate scroll;
#[macro_use]
extern crate structopt_derive;

use goblin::{error, Hint, pe, elf, mach, archive, container};
use scroll::Buffer;
use std::path::Path;
use std::fs::File;

use colored::Colorize;
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

struct MachO<'a>(mach::MachO<'a>);

impl<'a> ::std::fmt::Display for MachO<'a> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        use mach::header;
        use mach::load_command;
        use mach::exports::{Export};

        let mach = &self.0;
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
        let addr = |addr: u64| {
            format!("{:x}",addr).red()
        };
        let addrx = |addr: u64| {
            format!("{:#x}",addr).red()
        };
        let off = |off: u64| {
            format!("{:#x}",off).yellow()
        };
        let _offs = |off: isize| {
            format!("{:#x}",off).yellow()
        };
        let string = |s: &str| {
            s.reverse().bold().yellow()
        };
        let sz = |sz: u64| {
            format!("{:#x}", sz).green()
        };
        let idx = |i| {
            let index = format!("{:>4}", i);
            if i % 2 == 0 { index.white().on_black() } else { index.black().on_white() }
        };

        let header = &mach.header;
        let endianness = if header.is_little_endian() { "little-endian" } else { "big-endian" };
        let kind = {
            let typ = header.filetype;
            let kind_str = header::filetype_to_str(typ).reverse().bold();
            match typ {
                header::MH_OBJECT =>  kind_str.yellow(),
                header::MH_EXECUTE => kind_str.red(),
                header::MH_DYLIB =>  kind_str.blue(),
                header::MH_DYLINKER =>  kind_str.yellow(),
                header::MH_DYLIB_STUB =>  kind_str.blue(),
                header::MH_DSYM =>  kind_str.green(),
                header::MH_CORE => kind_str.black(),
                _ => kind_str.normal(),
            }
        };
        let machine = header.cputype;
        let machine_str = {
            mach::constants::cputype::cpu_type_to_str(machine).bold()
        };
        writeln!(fmt, "{} {} {}-{} @ {}:",
                 hdr("Mach-o"),
                 kind,
                 machine_str,
                 endianness,
                 addrx(mach.entry as u64),
        )?;
        writeln!(fmt, "")?;

        let lcs = &mach.load_commands;
        fmt_header(fmt, "LoadCommands", mach.load_commands.len())?;
        for (i, lc) in lcs.into_iter().enumerate() {
            let name = {
                let name = load_command::cmd_to_str(lc.command.cmd());
                let name = format!("{:.27}", name);
                match lc.command {
                    load_command::CommandVariant::Segment32        (_command) => name.red(),
                    load_command::CommandVariant::Segment64        (_command) => name.red(),
                    load_command::CommandVariant::Symtab           (_command) => name.yellow(),
                    load_command::CommandVariant::Dysymtab         (_command) => name.green(),
                    load_command::CommandVariant::LoadDylinker     (_command) => name.yellow(),
                    load_command::CommandVariant::LoadDylib        (_command)
                    | load_command::CommandVariant::LoadUpwardDylib(_command)
                    | load_command::CommandVariant::ReexportDylib  (_command)
                    | load_command::CommandVariant::LazyLoadDylib  (_command) => name.blue(),
                    load_command::CommandVariant::DyldInfo         (_command)
                    | load_command::CommandVariant::DyldInfoOnly   (_command) => name.cyan(),
                    load_command::CommandVariant::Unixthread       (_command) => name.red(),
                    load_command::CommandVariant::Main             (_command) => name.red(),
                    _ => name.normal(),
                }
            };
            write!(fmt, "{} ", idx(i))?;
            writeln!(fmt, "{:<27} ", name)?;
        }

        writeln!(fmt, "")?;
        use scroll::Pread;
        let fmt_section = |fmt: &mut ::std::fmt::Formatter, i: usize, section: &load_command::Section | -> ::std::fmt::Result {
            let name = section.sectname.pread::<&str>(0).unwrap();
            write!(fmt,   "    {}: {:>16}", idx(i), string(name))?;
            write!(fmt,   "    addr: {:>8} ",     addr(section.addr))?;
            write!(fmt,   "    size: {:>8} ",     sz(section.size))?;
            write!(fmt,   "    offset: {:>8} ",   off(section.offset as u64))?;
            write!(fmt,   "    align: {} ",    section.align)?;
            write!(fmt,   "    reloff: {} ",   off(section.reloff as u64))?;
            write!(fmt,   "    nreloc: {} ",   section.nreloc)?;
            write!(fmt,   "    flags: {:#10x} ",    section.flags)?;
            writeln!(fmt, "    data: {}",    section.data.len())
        };

        let fmt_sections = |fmt: &mut ::std::fmt::Formatter, name: &str, sections: &[load_command::Section] | -> ::std::fmt::Result {
            writeln!(fmt, "  {}", hdr_size(name, sections.len()).yellow())?;
            for (i, section) in sections.into_iter().enumerate() {
                fmt_section(fmt, i, &section)?;
            }
            Ok(())
        };

        let segments = &*mach.segments;
        fmt_header(fmt, "Segments", segments.len())?;
        for (ref i, ref segment) in segments.into_iter().enumerate() {
            write!(fmt, "  {}:",     (*i).to_string().yellow())?;
            let name = segment.name().unwrap();
            fmt_sections(fmt, name, &segment.sections().unwrap())?;
        }

        writeln!(fmt, "")?;

        let fmt_exports = |fmt: &mut ::std::fmt::Formatter, name: &str, syms: &[Export] | -> ::std::fmt::Result {
            fmt_header(fmt, name, syms.len())?;
            for sym in syms {
                write!(fmt, "{:>16} ", addr(sym.offset))?;
                write!(fmt, "{} ", string(&sym.name))?;
                writeln!(fmt, "({})", sz(sym.size as u64))?;
            }
            writeln!(fmt, "")
        };

        let exports = match mach.exports () { Ok(exports) => exports, Err(_) => Vec::new() };
        fmt_exports(fmt, "Exports", &exports)?;

        let imports = match mach.imports () { Ok(imports) => imports, Err(_) => Vec::new() };
        fmt_header(fmt, "Imports", imports.len())?;
        for sym in imports {
            write!(fmt, "{:>16} ", addr(sym.offset))?;
            write!(fmt, "{} ", string(&sym.name))?;
            write!(fmt, "({})", sz(sym.size as u64))?;
            writeln!(fmt, "-> {}", string(sym.dylib).blue())?;
        }
        writeln!(fmt, "")?;

        fmt_header(fmt, "Libraries", mach.libs.len())?;
        for lib in &mach.libs[1..] {
            writeln!(fmt, "{:>16} ", string(lib).blue())?;
        }
        writeln!(fmt, "")?;

        writeln!(fmt, "Name: {}", if let &Some(ref name) = &mach.name{ name } else { "None" })?;
        writeln!(fmt, "is_64: {}", mach.header.container() == container::Container::Big )?;
        writeln!(fmt, "is_lib: {}", mach.header.filetype == header::MH_DYLIB)?;
        writeln!(fmt, "little_endian: {}", mach.header.is_little_endian())?;
        writeln!(fmt, "entry: {}", addr(mach.entry as u64))?;

        Ok(())
    }
}

struct Elf<'a> {
    elf: elf::Elf<'a>,
}

impl<'a> ::std::fmt::Display for Elf<'a> {
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
            s.reverse().bold().yellow()
        };
        let sz = |sz| {
            format!("{:#x}", sz).green()
        };
        let idx = |i| {
            let index = format!("{:>4}", i);
            if i % 2 == 0 { index.white().on_black() } else { index.black().on_white() }
        };

        let header = &self.elf.header;
        let endianness = if self.elf.little_endian { "little-endian" } else { "big-endian" };
        let kind = {
            let typ = header.e_type;
            let kind_str = header::et_to_str(typ).reverse().bold();
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
        let phdrs = &self.elf.program_headers;
        for (i, phdr) in phdrs.into_iter().enumerate() {
            let name = {
                let typ = phdr.p_type;
                let name = format!("{:.16}", program_header::pt_to_str(typ));
                match typ {
                    program_header::PT_LOAD    => name.red(),
                    program_header::PT_INTERP  => name.yellow(),
                    program_header::PT_DYNAMIC => name.cyan(),
                    _ => name.normal()
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
            write!(fmt, "{} ", idx(i))?;
            write!(fmt, "{:<16} ", name)?;
            write!(fmt, "{:>4} ", flags)?;
            write!(fmt, "p_offset: {:<16} ", off(phdr.p_offset))?;
            write!(fmt, "p_vaddr: {:<16} ", addrx(phdr.p_vaddr))?;
            write!(fmt, "p_paddr: {:<16} ", addrx(phdr.p_paddr).bold())?;
            write!(fmt, "p_filesz: {:<16} ", sz(phdr.p_filesz))?;
            write!(fmt, "p_memsz: {:<16} ", sz(phdr.p_memsz).bold())?;
            write!(fmt, "p_flags: {:#x} ", phdr.p_flags)?;
            writeln!(fmt, "p_align: {:#x}", phdr.p_align)?;
        }
        writeln!(fmt, "")?;

        fmt_header(fmt, "SectionHeaders", self.elf.section_headers.len())?;
        let shdr_strtab = &self.elf.shdr_strtab;
        for (i, shdr) in (&self.elf.section_headers).into_iter().enumerate() {
            let name = {
                let name = format!("{:.16}", &shdr_strtab[shdr.sh_name]);
                if i % 2 == 0 { name.white().on_black() } else { name.black().on_white() }
            };
            write!(fmt, "{} {:<16} ", idx(i), name)?;
            write!(fmt, "{} ", section_header::sht_to_str(shdr.sh_type))?;
            write!(fmt, "sh_offset: {} ", off(shdr.sh_offset))?;
            write!(fmt, "sh_addr: {} ", addrx(shdr.sh_addr))?;
            write!(fmt, "sh_size: {} ", sz(shdr.sh_size))?;
            write!(fmt, "sh_link: {} "   , shdr.sh_link)?;
            write!(fmt, "sh_info: {:#x} ", shdr.sh_info)?;
            write!(fmt, "sh_entsize: {:#x} ", shdr.sh_entsize)?;
            write!(fmt, "sh_flags: {:#x} ", shdr.sh_flags)?;
            writeln!(fmt, "sh_addralign: {:#x}", shdr.sh_addralign)?;
        }
        writeln!(fmt, "")?;

        let fmt_syms = |fmt: &mut ::std::fmt::Formatter, name: &str, syms: &Syms, strtab: &Strtab | -> ::std::fmt::Result {
            fmt_header(fmt, name, syms.len())?;
            for sym in syms {
                let bind = {
                    let bind_str = format!("{:.8}", sym::bind_to_str(sym.st_bind())).reverse().bold();
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
                let name = if sym.st_name == 0 {
                    if sym.st_type() == sym::STT_SECTION {
                        let shdr = &self.elf.section_headers[sym.st_shndx];
                        shdr_strtab[shdr.sh_name].dimmed()
                    } else {
                        "ABS".dimmed()
                    }
                } else {
                    string(&strtab[sym.st_name])
                };
                write!(fmt, "{} ",  reloc::r_to_str(reloc.r_type, machine))?;
                let addend = if reloc.r_addend == 0 {
                    "".normal()
                } else {
                    format!("+{}", offs(reloc.r_addend)).normal()
                };
                writeln!(fmt, "{}{}", name, addend)?;
            }
            writeln!(fmt, "")?;
            Ok(())
        };

        fmt_header(fmt, "Dynamic Relas", self.elf.dynrelas.len())?;
        fmt_relocs(fmt,  &self.elf.dynrelas, &self.elf.dynsyms, &dyn_strtab)?;
        fmt_header(fmt, "Dynamic Rel", self.elf.dynrels.len())?;
        fmt_relocs(fmt,  &self.elf.dynrels, &self.elf.dynsyms, &dyn_strtab)?;
        fmt_header(fmt, "Plt Relocations", self.elf.pltrelocs.len())?;
        fmt_relocs(fmt, &self.elf.pltrelocs, &self.elf.dynsyms, &dyn_strtab)?;

        // ewwwwww, this ain't no ocaml fold
        let num_shdr_relocs = self.elf.shdr_relocs.iter().fold(0, &|acc, &(_, ref v): &(usize, Vec<_>)| acc + v.len());
        fmt_header(fmt, "Shdr Relocations", num_shdr_relocs)?;
        if num_shdr_relocs != 0 {
            for &(idx, ref relocs) in &self.elf.shdr_relocs {
                let ref shdr = self.elf.section_headers[idx];
                let shdr = &self.elf.section_headers[shdr.sh_info as usize];
                let name = &shdr_strtab[shdr.sh_name];
                writeln!(fmt, "  {}({})", name.bold(), relocs.len())?;
                fmt_relocs(fmt, &relocs.as_slice(), &self.elf.syms, &strtab)?;
            }
        }

        fmt_header(fmt, "Libraries", self.elf.libraries.len())?;
        for lib in &self.elf.libraries {
            writeln!(fmt, "{:>16} ", string(lib).blue())?;
        }
        writeln!(fmt, "")?;

        writeln!(fmt, "Soname: {:?}", self.elf.soname)?;
        writeln!(fmt, "Interpreter: {}", if let &Some(ref interpreter) = &self.elf.interpreter{ interpreter } else { "None" })?;
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
    let peek = goblin::peek(&mut fd)?;
    if let Hint::Unknown(magic) = peek {
        println!("unknown magic: {:#x}", magic)
    } else {
        let bytes = Buffer::try_from(fd)?;
        match peek {
            Hint::Elf(_) => {
                let elf = elf::Elf::parse(&bytes)?;
                if opt.debug {
                    println!("{:#?}", elf);
                } else {
                    println!("{}", Elf {elf: elf});
                }
            },
            Hint::PE => {
                let pe = pe::PE::parse(&bytes)?;
                println!("pe: {:#?}", &pe);
            },
            Hint::MachFat(_) => {
                let mach = mach::Mach::parse(&bytes)?;
                if opt.debug {
                    println!("{:#?}", mach);
                } else {
                    match mach {
                        mach::Mach::Fat(multi) => {
                            for i in 0..multi.narches {
                                match multi.get(i) {
                                    Ok(binary) => {
                                        println!("{}", MachO(binary));
                                    },
                                    Err(err) => {
                                        println!("{}", err);
                                    }
                                }
                            }
                        },
                        mach::Mach::Binary(binary) => {
                            println!("{}", MachO(binary));
                        }
                    }
                }
            }
            Hint::Mach(_) => {
                let mach = mach::MachO::parse(&bytes, 0)?;
                if opt.debug {
                    println!("{:#?}", mach);
                } else {
                    println!("{}", MachO(mach));
                }
             },
            Hint::Archive => {
                let archive = archive::Archive::parse(&bytes)?;
                println!("archive: {:#?}", &archive);
            },
            _ => unreachable!()
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
