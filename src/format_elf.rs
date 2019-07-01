use metagoblin;
use metagoblin::elf;
use Opt;

use failure::Error;
use atty;
use scroll::Pread;
use termcolor::*;
use termcolor::Color::*;
use std::io::Write;
use scroll::ctx::StrCtx;
use prettytable::Cell;
use prettytable::Row;
use format::*;

use elf::header;
use elf::program_header;
use elf::section_header;
use elf::sym;
use elf::dynamic;
use elf::Dynamic;
use elf::RelocSection;
use metagoblin::strtab::Strtab;
use elf::reloc;

type Syms = Vec<sym::Sym>;

fn shndx_cell (opt: &Opt, idx: usize, shdrs: &elf::SectionHeaders, strtab: &metagoblin::strtab::Strtab) -> Cell {
    if idx >= shdrs.len() {
        if idx == 0xfff1 { // associated symbol is absolute, todo, move this to goblin
            Cell::new(&format!("ABS")).style_spec("iFw")
        } else {
            Cell::new(&format!("BAD_IDX={}", idx)).style_spec("irFw")
        }
    } else if idx != 0 {
        let shdr = &shdrs[idx];
        let link_name = truncate(opt, &strtab[shdr.sh_name]);
        Cell::new(&format!("{}({})", link_name, idx))
    } else {
        Cell::new("")
    }
}

pub struct Elf<'a> {
    elf: elf::Elf<'a>,
    bytes: &'a [u8],
    args: Opt,
}

impl<'a> Elf<'a> {
    pub fn new(elf: elf::Elf<'a>,
               bytes: &'a [u8],
               args: Opt) -> Self {
        Elf {
            elf: elf,
            bytes: bytes,
            args: args,
        }
    }

    pub fn search(&self, search: &String) -> Result<(), Error> {
        let cc = if self.args.color || atty::is(atty::Stream::Stdout) { ColorChoice::Auto } else { ColorChoice::Never };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let mut matches = Vec::new();
        for i in 0..self.bytes.len() {
            match self.bytes.pread_with::<&str>(i, StrCtx::Length(search.len())) {
                Ok(res) => {
                    if res == search {
                        matches.push(i);
                    }
                },
                _ => (),
            }
        }

        writeln!(fmt)?;
        writeln!(fmt, "Matches for {:?}:", search)?;
        let _match_table = new_table(row!["Phdr", "Shdr"]);
        let normalize = |offset: usize, base_offset: u64, base: u64| -> u64 {
            (offset as u64 - base_offset) + base
        };
        for offset in matches {
            writeln!(fmt, "  {:#x}", offset)?;
            let shdr_strtab = &self.elf.shdr_strtab;
            for (i, phdr) in (&self.elf.program_headers).into_iter().enumerate() {
                if offset as u64 >= phdr.p_offset && (offset as u64) < (phdr.p_offset + phdr.p_filesz) {
                    write!(fmt, "  ├──{}({}) ∈ ", program_header::pt_to_str(phdr.p_type), i)?;
                    fmt_addrx(fmt, normalize(offset, phdr.p_offset, phdr.p_vaddr))?;
                    writeln!(fmt, "")?;
                }
            }
            for (i, shdr) in (&self.elf.section_headers).into_iter().enumerate() {
                if offset as u64 >= shdr.sh_offset && (offset as u64) < (shdr.sh_offset + shdr.sh_size) {
                    write!(fmt, "  ├──{}({}) ∈ ", &shdr_strtab[shdr.sh_name], i)?;
                    fmt_addrx(fmt, normalize(offset, shdr.sh_offset, shdr.sh_addr))?;
                    writeln!(fmt, "")?;
                    // use prettytable::Slice;
                    // let slice = shdr_table.slice(i..i+1);
                    // slice.printstd();
                }
            }
        }
        writer.print(&fmt)?;
        Ok(())
    }

    pub fn print(&self) -> Result<(), Error> {
        let args = &self.args;
        let color = args.color;

        let cc = if args.color || atty::is(atty::Stream::Stdout) { ColorChoice::Auto } else { ColorChoice::Never };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let header = &self.elf.header;
        let endianness = if self.elf.little_endian { "little-endian" } else { "big-endian" };
        let kind = |fmt: &mut Buffer, header: &elf::Header| {
            let typ = header.e_type;
            let kind_str = header::et_to_str(typ);
            match typ {
                header::ET_REL =>  fmt.set_color(::termcolor::ColorSpec::new().set_intense(true).set_bg(Some(Yellow)).set_fg(Some(Black)))?,
                header::ET_EXEC => fmt.set_color(::termcolor::ColorSpec::new().set_intense(true).set_bg(Some(Red))   .set_fg(Some(Black)))?,
                header::ET_DYN =>  fmt.set_color(::termcolor::ColorSpec::new().set_intense(true).set_bg(Some(Blue))  .set_fg(Some(Black)))?,
                header::ET_CORE => fmt.set_color(::termcolor::ColorSpec::new().set_intense(true).set_bg(Some(Black)) .set_fg(Some(Black)))?,
                _ => (),
            }
            write!(fmt, "{}", kind_str)?;
            fmt.reset()
        };
        let machine = header.e_machine;
        fmt_hdr(fmt, "ELF ")?;
        kind(fmt, &header)?;
        write!(fmt, " ")?;
        fmt_name_bold(fmt, header::machine_to_str(machine))?;
        write!(fmt, "-{} @ ", endianness)?;
        fmt_addrx(fmt, self.elf.entry as u64)?;
        writeln!(fmt, ":")?;
        writeln!(fmt, "")?;
        write!(fmt, "e_phoff: ")?;
        fmt_off(fmt, header.e_phoff)?;
        write!(fmt, " e_shoff: ")?;
        fmt_off(fmt, header.e_shoff)?;
        writeln!(fmt, " e_flags: {:#x} e_ehsize: {} e_phentsize: {} e_phnum: {} e_shentsize: {} e_shnum: {} e_shstrndx: {}",
                 header.e_flags,
                 header.e_ehsize,
                 header.e_phentsize,
                 header.e_phnum,
                 header.e_shentsize,
                 header.e_shnum,
                 header.e_shstrndx,
        )?;
        writeln!(fmt, "")?;
        let ph_flag = |phdr: &elf::ProgramHeader| {
            let wx = program_header::PF_W|program_header::PF_X;
            let rx = program_header::PF_R|program_header::PF_X;
            let rwx = program_header::PF_R|program_header::PF_W|program_header::PF_X;
            let rw = program_header::PF_R|program_header::PF_W;
            let flags = phdr.p_flags;
            if flags == rwx { "RW+X".to_owned() }
            else if flags == rw { "RW".to_owned() }
            else if flags == rx { "R+X".to_owned() }
            else if flags == wx { "W+X".to_owned() }
            else if flags == program_header::PF_R { "R".to_owned() }
            else if flags == program_header::PF_W { "W".to_owned() }
            else if flags == program_header::PF_R { "R".to_owned() }
            else { format!("{:#x}", flags) }
        };

        fmt_header(fmt, "ProgramHeaders", self.elf.program_headers.len())?;
        let phdrs = &self.elf.program_headers;
        let mut phdr_table = new_table(row![b->"Idx", b->"Type", b->"Flags", b->"Offset", b->"Vaddr", b->"Paddr", b->"Filesz", b->"Memsz", b->"Align"]);
        let ph_name_table = |phdr: &elf::ProgramHeader| {
            let typ_cell = phdr.p_type;
            let name = program_header::pt_to_str(typ_cell);
            match typ_cell {
                program_header::PT_LOAD    => Cell::new(name).style_spec("Fr"),
                program_header::PT_INTERP  => Cell::new(name).style_spec("Fy"),
                program_header::PT_DYNAMIC => Cell::new(name).style_spec("Fc"),
                _ =>  Cell::new(name),
            }
        };
        for (i, phdr) in phdrs.into_iter().enumerate() {
            let name_cell = ph_name_table(&phdr);
            let flags = ph_flag(&phdr);
            phdr_table.add_row(Row::new(vec![
                Cell::new(&i.to_string()),
                name_cell,
                Cell::new(&flags),
                offsetx_cell(phdr.p_offset),
                addrx_cell(phdr.p_vaddr),
                memx_cell(phdr.p_paddr),
                sz_cell(phdr.p_filesz),
                memsz_cell(phdr.p_filesz),
                x_cell(phdr.p_align),
            ]));
        }
        flush(fmt, &writer, phdr_table, color)?;
        writeln!(fmt, "")?;

        if let Some(mut notes) = self.elf.iter_note_headers(self.bytes) {
            fmt_hdr(fmt, "Notes")?;
            writeln!(fmt, "")?;
            let mut i = 0;
            while let Some(Ok(note)) = notes.next() {
               fmt_idx(fmt, i)?;
                write!(fmt, " ")?;
                fmt_str(fmt, note.name.trim_end_matches('\0'))?;
                write!(fmt, " type: {} ", note.type_to_str())?;
                for byte in note.desc {
                    write!(fmt, "{:x}", byte)?;
                }
                writeln!(fmt, "")?;
                i += 1;
            }
            writeln!(fmt, "")?;
        }

        fmt_header(fmt, "SectionHeaders", self.elf.section_headers.len())?;
        let shdr_strtab = &self.elf.shdr_strtab;
        let mut shdr_table = new_table(row![b->"Idx", b->"Name", br->"Type", b->"Flags", b->"Offset", b->"Addr", b->"Size", b->"Link", b->"Entsize", b->"Align"]);
        for (i, shdr) in (&self.elf.section_headers).into_iter().enumerate() {
            let name_cell = {
                let name = &shdr_strtab[shdr.sh_name];
                name_even_odd_cell(args, i, name)
            };
            let flags_cell = {
                let shflags = shdr.sh_flags as u32;
                if shflags != 0 {
                    let mut flags = String::new();
                    for flag in &section_header::SHF_FLAGS {
                        let flag = *flag;
                        if shflags & flag == flag {
                            flags += &section_header::shf_to_str(flag).to_string().split_off(4);
                            flags += " ";
                        }
                    }
                    Cell::new(&flags).style_spec("lbW")
                } else {
                    Cell::new("")
                }
            };
            shdr_table.add_row(Row::new(vec![
                idx_cell(i),
                name_cell,
                Cell::new(section_header::sht_to_str(shdr.sh_type)).style_spec("r"),
                flags_cell,
                offsetx_cell(shdr.sh_offset),
                memx_cell(shdr.sh_addr),
                memsz_cell(shdr.sh_size),
                shndx_cell(args, shdr.sh_link as usize, &self.elf.section_headers, &self.elf.shdr_strtab),
                x_cell(shdr.sh_entsize),
                x_cell(shdr.sh_addralign),
            ]));
        }
        flush(fmt, &writer, shdr_table, color)?;
        writeln!(fmt, "")?;

        let fmt_syms = |fmt: &mut Buffer, name: &str, syms: &Syms, strtab: &Strtab | -> Result<(), Error> {
            fmt_header(fmt, name, syms.len())?;
            if syms.len() == 0 { return Ok(()); }
            let mut table = new_table(row![br->"Addr", bl->"Bind", bl->"Type", b->"Symbol", b->"Size", b->"Section", b->"Other"]);
            for sym in syms {
                let bind_cell = {
                    let bind_cell = Cell::new(&format!("{:<8}",sym::bind_to_str(sym.st_bind())));
                    match sym.st_bind() {
                        sym::STB_LOCAL => bind_cell.style_spec("bBCFD"),
                        sym::STB_GLOBAL => bind_cell.style_spec("bBRFD"),
                        sym::STB_WEAK => bind_cell.style_spec("bBMFD"),
                        _ => bind_cell
                    }
                };
                let typ_cell = {
                    let typ_cell = Cell::new(&format!("{:<9}", sym::type_to_str(sym.st_type())));
                    match sym.st_type() {
                        sym::STT_OBJECT => typ_cell.style_spec("bFY"),
                        sym::STT_FUNC => typ_cell.style_spec("bFR"),
                        sym::STT_GNU_IFUNC => typ_cell.style_spec("bFC"),
                        _ => typ_cell
                    }
                };
                let name = strtab.get(sym.st_name).unwrap_or(Ok("BAD NAME"))?;
                table.add_row(Row::new(vec![
                    addr_cell(sym.st_value),
                    bind_cell,
                    typ_cell,
                    string_cell(&self.args, &name),
                    sz_cell(sym.st_size),
                    shndx_cell(args, sym.st_shndx, &self.elf.section_headers, &self.elf.shdr_strtab),
                    Cell::new(&format!("{:#x} ", sym.st_other)),
                ]));
            }
            flush(fmt, &writer, table, color)?;
            writeln!(fmt, "")?;
            Ok(())
        };

        let dyn_strtab = &self.elf.dynstrtab;
        let strtab = &self.elf.strtab;
        let syms = self.elf.syms.to_vec();
        let dynsyms = self.elf.dynsyms.to_vec();
        fmt_syms(fmt, "Syms", &syms, strtab)?;
        fmt_syms(fmt, "Dyn Syms", &dynsyms, dyn_strtab)?;

        let fmt_relocs = |fmt: &mut Buffer, relocs: &RelocSection, syms: &Syms, strtab: &Strtab | -> Result<(), Error> {
            for reloc in relocs.iter() {
                fmt_addr_right(fmt, reloc.r_offset as u64)?;
                write!(fmt, " {} ",  reloc::r_to_str(reloc.r_type, machine))?;
                if let Some(sym) = &syms.get(reloc.r_sym) {
                    if sym.st_name == 0 {
                        if sym.st_type() == sym::STT_SECTION {
                            let shdr = &self.elf.section_headers[sym.st_shndx];
                            fmt_string(fmt, args, &shdr_strtab[shdr.sh_name])?;
                        } else {
                            fmt_name_dim(fmt, "ABS")?;
                        }
                    } else {
                        fmt_string(fmt, args, &strtab[sym.st_name])?;
                    }
                    if let Some(addend) = reloc.r_addend {
                        write!(fmt, "+")?;
                        fmt_isize(fmt, addend as isize)?;
                    }
                    writeln!(fmt, "")?;
                } else {
                    writeln!(fmt, "NO SYMBOL")?;
                }
            }
            writeln!(fmt, "")?;
            writer.print(fmt)?;
            fmt.clear();
            Ok(())
        };

        fmt_header(fmt, "Dynamic Relas", self.elf.dynrelas.len())?;
        fmt_relocs(fmt,  &self.elf.dynrelas, &dynsyms, &dyn_strtab)?;
        fmt_header(fmt, "Dynamic Rel", self.elf.dynrels.len())?;
        fmt_relocs(fmt,  &self.elf.dynrels, &dynsyms, &dyn_strtab)?;
        fmt_header(fmt, "Plt Relocations", self.elf.pltrelocs.len())?;
        fmt_relocs(fmt, &self.elf.pltrelocs, &dynsyms, &dyn_strtab)?;

        let num_shdr_relocs = self.elf.shdr_relocs.iter().fold(0, &|acc, &(_, ref v): &(usize, RelocSection)| acc + v.len());
        fmt_header(fmt, "Shdr Relocations", num_shdr_relocs)?;
        if num_shdr_relocs != 0 {
            for &(idx, ref relocs) in &self.elf.shdr_relocs {
                let ref shdr = self.elf.section_headers[idx];
                let shdr = &self.elf.section_headers[shdr.sh_info as usize];
                let name = &shdr_strtab[shdr.sh_name];
                fmt_name_bold(fmt, &format!("  {}", name))?;
                writeln!(fmt, "({})", relocs.len())?;
                fmt_relocs(fmt, &relocs, &syms, &strtab)?;
            }
        }
        writeln!(fmt, "")?;

        if let &Some(Dynamic { ref dyns, .. }) = &self.elf.dynamic {
            fmt_header(fmt, "Dynamic", dyns.len())?;
            for dyn_sym in dyns {
                let tag = dyn_sym.d_tag;
                let val = dyn_sym.d_val;
                let tag_str = dynamic::tag_to_str(tag);
                fmt_cyan(fmt, &format!("{:>16} ", tag_str))?;
                match tag {
                    dynamic::DT_RPATH => fmt_string(fmt, &self.args, &dyn_strtab[val as usize])?,
                    dynamic::DT_NEEDED => fmt_lib(fmt, &dyn_strtab[val as usize])?,
                    dynamic::DT_INIT => fmt_addrx(fmt, val)?,
                    dynamic::DT_FINI => fmt_addrx(fmt, val)?,
                    dynamic::DT_INIT_ARRAY => fmt_addrx(fmt, val)?,
                    dynamic::DT_INIT_ARRAYSZ => fmt_sz(fmt, val)?,
                    dynamic::DT_FINI_ARRAY => fmt_addrx(fmt, val)?,
                    dynamic::DT_FINI_ARRAYSZ => fmt_sz(fmt, val)?,
                    dynamic::DT_GNU_HASH => fmt_addrx(fmt, val)?,
                    dynamic::DT_STRTAB => fmt_addrx(fmt, val)?,
                    dynamic::DT_SYMTAB => fmt_addrx(fmt, val)?,
                    dynamic::DT_STRSZ => fmt_sz(fmt, val)?,
                    dynamic::DT_PLTGOT => fmt_addrx(fmt, val)?,
                    dynamic::DT_PLTRELSZ => fmt_sz(fmt, val)?,
                    dynamic::DT_JMPREL => fmt_addrx(fmt, val)?,
                    dynamic::DT_RELA => fmt_addrx(fmt, val)?,
                    dynamic::DT_RELASZ => fmt_sz(fmt, val)?,
                    dynamic::DT_VERNEED => fmt_addrx(fmt, val)?,
                    dynamic::DT_VERSYM => fmt_addrx(fmt, val)?,
                    _ => write!(fmt, "{:#x}", dyn_sym.d_val)?,
                }
                writeln!(fmt, "")?;
            }
        } else {
            writeln!(fmt, "{}: None", "Dynamic")?;
        }
        writeln!(fmt, "")?;
        writeln!(fmt, "")?;

        fmt_header(fmt, "Libraries", self.elf.libraries.len())?;
        for lib in &self.elf.libraries {
            fmt_lib(fmt, &format!("{:>16}", lib))?;
            writeln!(fmt, "")?;
        }
        writeln!(fmt, "")?;

        write!(fmt, "Soname: ")?;
        fmt_str_option(fmt, &self.elf.soname)?;
        writeln!(fmt, "")?;
        write!(fmt, "Interpreter: ")?;
        fmt_str_option(fmt, &self.elf.interpreter)?;
        writeln!(fmt, "")?;
        write!(fmt, "is_64: ")?;
        fmt_bool(fmt, self.elf.is_64)?;
        writeln!(fmt, "")?;
        write!(fmt, "is_lib: ")?;
        fmt_bool(fmt, self.elf.is_lib)?;
        writeln!(fmt, "")?;
        write!(fmt, "little_endian: ")?;
        fmt_bool(fmt, self.elf.little_endian)?;
        writeln!(fmt, "")?;
        write!(fmt, "entry: ")?;
        fmt_addr(fmt, self.elf.entry as u64)?;
        writeln!(fmt, "")?;

        writer.print(fmt)?;
        Ok(())
    }
}
