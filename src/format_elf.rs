use std::io::{stdout, IsTerminal, Write};

use anyhow::Error;
use metagoblin::elf;
use metagoblin::elf::{
    dynamic, header, program_header, reloc, section_header, sym, Dynamic, RelocSection,
};
use metagoblin::strtab::Strtab;
use prettytable::{row, Cell, Row, Table};
use scroll::ctx::StrCtx;
use scroll::Pread;
use termcolor::Color::*;
use termcolor::{Buffer, BufferWriter, ColorChoice, ColorSpec, WriteColor};

use crate::format::*;
use crate::Opt;

type Syms = Vec<sym::Sym>;

fn shndx_cell(
    opt: &Opt,
    idx: usize,
    shdrs: &elf::SectionHeaders,
    strtab: &metagoblin::strtab::Strtab,
) -> Cell {
    if idx == 0 {
        Cell::new("")
    } else if let Some(shdr) = shdrs.get(idx) {
        if let Some(link_name) = strtab.get_at(shdr.sh_name).map(move |s| truncate(opt, s)) {
            Cell::new(&format!("{}({})", link_name, idx))
        } else {
            Cell::new(&format!("BAD_IDX={}", shdr.sh_name)).style_spec("irFw")
        }
    } else if idx == 0xfff1 {
        // Associated symbol is absolute.
        // TODO: move this to goblin.
        Cell::new("ABS").style_spec("iFw")
    } else {
        Cell::new(&format!("BAD_IDX={}", idx)).style_spec("irFw")
    }
}

pub struct Elf<'bytes> {
    elf: elf::Elf<'bytes>,
    bytes: &'bytes [u8],
    args: Opt,
}

impl<'bytes> Elf<'bytes> {
    pub fn new(elf: elf::Elf<'bytes>, bytes: &'bytes [u8], args: Opt) -> Self {
        Elf { elf, bytes, args }
    }

    fn normalize(offset: u64, base_offset: u64, base: u64) -> u64 {
        assert!(offset >= base_offset);
        base + (offset - base_offset)
    }

    pub fn search(&self, search: &str) -> Result<(), Error> {
        let cc = if self.args.color || stdout().is_terminal() {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let mut matches = Vec::new();
        for i in 0..self.bytes.len() {
            if let Ok(res) = self
                .bytes
                .pread_with::<&str>(i, StrCtx::Length(search.len()))
            {
                if res == search {
                    matches.push(i);
                }
            }
        }

        writeln!(fmt)?;
        writeln!(fmt, "Matches for {:?}:", search)?;
        let _match_table = new_table(row!["Phdr", "Shdr"]);
        for offset in matches.into_iter().map(u64::try_from) {
            let offset = offset?;

            writeln!(fmt, "  {:#x}", offset)?;
            let shdr_strtab = &self.elf.shdr_strtab;
            for (i, phdr) in self.elf.program_headers.iter().enumerate() {
                let offset_end = phdr.p_offset.saturating_add(phdr.p_filesz);
                if offset >= phdr.p_offset && offset < offset_end {
                    let type_str = program_header::pt_to_str(phdr.p_type);
                    write!(fmt, "  ├──{}({}) ∈ ", type_str, i)?;
                    fmt_addrx(fmt, Self::normalize(offset, phdr.p_offset, phdr.p_vaddr))?;
                    writeln!(fmt)?;
                }
            }
            for (i, shdr) in self.elf.section_headers.iter().enumerate() {
                let offset_end = shdr.sh_offset.saturating_add(shdr.sh_size);
                if offset >= shdr.sh_offset && offset < offset_end {
                    let name = shdr_strtab.get_at(shdr.sh_name).unwrap_or("<error>");
                    write!(fmt, "  ├──{}({}) ∈ ", name, i)?;
                    fmt_addrx(fmt, Self::normalize(offset, shdr.sh_offset, shdr.sh_addr))?;
                    writeln!(fmt)?;
                    // use prettytable::Slice;
                    // let slice = shdr_table.slice(i..i+1);
                    // slice.printstd();
                }
            }
        }
        writer.print(fmt)?;
        Ok(())
    }

    fn color_spec(bg: termcolor::Color, fg: termcolor::Color) -> ColorSpec {
        let mut color = ColorSpec::new();
        color.set_intense(true).set_bg(Some(bg)).set_fg(Some(fg));
        color
    }

    fn kind(fmt: &mut Buffer, header: &elf::Header) -> Result<(), Error> {
        let cs = match header.e_type {
            header::ET_REL => Some(Self::color_spec(Yellow, Black)),
            header::ET_EXEC => Some(Self::color_spec(Red, Black)),
            header::ET_DYN => Some(Self::color_spec(Blue, Black)),
            header::ET_CORE => Some(Self::color_spec(Black, Black)),
            _ => None,
        };
        if let Some(cs) = cs {
            fmt.set_color(&cs)?;
        }
        write!(fmt, "{}", header::et_to_str(header.e_type))?;
        fmt.reset().map_err(Into::into)
    }

    fn ph_flag(phdr: &elf::ProgramHeader) -> String {
        use program_header::{PF_R, PF_W, PF_X};

        if phdr.p_flags == (PF_R | PF_W | PF_X) {
            "RW+X".to_owned()
        } else if phdr.p_flags == (PF_R | PF_W) {
            "RW".to_owned()
        } else if phdr.p_flags == (PF_R | PF_X) {
            "R+X".to_owned()
        } else if phdr.p_flags == (PF_W | PF_X) {
            "W+X".to_owned()
        } else if phdr.p_flags == PF_R {
            "R".to_owned()
        } else if phdr.p_flags == PF_W {
            "W".to_owned()
        } else if phdr.p_flags == PF_X {
            "X".to_owned()
        } else {
            format!("{:#x}", phdr.p_flags)
        }
    }

    fn ph_name_table(phdr: &elf::ProgramHeader) -> Cell {
        use program_header::{pt_to_str, PT_DYNAMIC, PT_INTERP, PT_LOAD};

        let name = pt_to_str(phdr.p_type);
        match phdr.p_type {
            PT_LOAD => Cell::new(name).style_spec("Fr"),
            PT_INTERP => Cell::new(name).style_spec("Fy"),
            PT_DYNAMIC => Cell::new(name).style_spec("Fc"),
            _ => Cell::new(name),
        }
    }

    fn fmt_symbol(&self, sym: &sym::Sym, strtab: &Strtab, table: &mut Table) {
        let bind_cell = {
            let bind_cell = Cell::new(&format!("{:<8}", sym::bind_to_str(sym.st_bind())));
            match sym.st_bind() {
                sym::STB_LOCAL => bind_cell.style_spec("bBCFD"),
                sym::STB_GLOBAL => bind_cell.style_spec("bBRFD"),
                sym::STB_WEAK => bind_cell.style_spec("bBMFD"),
                _ => bind_cell,
            }
        };
        let typ_cell = {
            let typ_cell = Cell::new(&format!("{:<9}", sym::type_to_str(sym.st_type())));
            match sym.st_type() {
                sym::STT_OBJECT => typ_cell.style_spec("bFY"),
                sym::STT_FUNC => typ_cell.style_spec("bFR"),
                sym::STT_GNU_IFUNC => typ_cell.style_spec("bFC"),
                _ => typ_cell,
            }
        };
        let name = strtab.get_at(sym.st_name).unwrap_or("BAD NAME");
        table.add_row(Row::new(vec![
            addr_cell(sym.st_value),
            bind_cell,
            typ_cell,
            string_cell(&self.args, name),
            sz_cell(sym.st_size),
            shndx_cell(
                &self.args,
                sym.st_shndx,
                &self.elf.section_headers,
                &self.elf.shdr_strtab,
            ),
            Cell::new(&format!("{:#x} ", sym.st_other)),
        ]));
    }

    fn fmt_syms(
        &self,
        fmt: &mut Buffer,
        writer: &BufferWriter,
        name: &str,
        syms: &Syms,
        strtab: &Strtab,
    ) -> Result<(), Error> {
        fmt_header(fmt, name, syms.len())?;
        if syms.is_empty() {
            return Ok(());
        }
        let mut table = new_table(
            row![br->"Addr", bl->"Bind", bl->"Type", b->"Symbol", b->"Size", b->"Section", b->"Other"],
        );
        syms.iter()
            .for_each(|sym| self.fmt_symbol(sym, strtab, &mut table));
        flush(fmt, writer, &table, self.args.color)?;
        writeln!(fmt)?;
        Ok(())
    }

    fn fmt_relocation(
        &self,
        fmt: &mut Buffer,
        strtab: &Strtab,
        sym: &metagoblin::elf::Sym,
        reloc: metagoblin::elf::Reloc,
    ) -> Result<(), Error> {
        if sym.st_name == 0 {
            if sym.st_type() == sym::STT_SECTION {
                let name = self
                    .elf
                    .section_headers
                    .get(sym.st_shndx)
                    .and_then(|shdr| self.elf.shdr_strtab.get_at(shdr.sh_name))
                    .unwrap_or("<error>");

                fmt_string(fmt, &self.args, name)?;
            } else {
                fmt_name_dim(fmt, "ABS")?;
            }
        } else {
            let name = strtab.get_at(sym.st_name).unwrap_or("<error>");
            fmt_string(fmt, &self.args, name)?;
        }
        if let Some(addend) = reloc.r_addend {
            write!(fmt, "+")?;
            fmt_isize(fmt, isize::try_from(addend)?)?;
        }
        writeln!(fmt).map_err(Into::into)
    }

    fn fmt_relocations(
        &self,
        fmt: &mut Buffer,
        writer: &BufferWriter,
        relocs: &RelocSection,
        syms: &Syms,
        strtab: &Strtab,
        machine: u16,
    ) -> Result<(), Error> {
        for reloc in relocs.iter() {
            fmt_addr_right(fmt, reloc.r_offset)?;
            write!(fmt, " {} ", reloc::r_to_str(reloc.r_type, machine))?;
            if let Some(sym) = syms.get(reloc.r_sym) {
                self.fmt_relocation(fmt, strtab, sym, reloc)?;
            } else {
                writeln!(fmt, "NO SYMBOL")?;
            }
        }
        writeln!(fmt)?;
        writer.print(fmt)?;
        fmt.clear();
        Ok(())
    }

    fn flags_cell(shdr: &metagoblin::elf::SectionHeader) -> Result<Cell, Error> {
        if shdr.sh_flags == 0 {
            return Ok(Cell::new(""));
        }

        let shflags = u32::try_from(shdr.sh_flags)?;
        let mut flags = String::new();
        for &flag in &section_header::SHF_FLAGS {
            if shflags & flag == flag {
                flags += &section_header::shf_to_str(flag).to_owned().split_off(4);
                flags += " ";
            }
        }
        Ok(Cell::new(&flags).style_spec("lbW"))
    }

    fn print_program_header(phdr_table: &mut Table, index: usize, phdr: &elf::ProgramHeader) {
        let name_cell = Self::ph_name_table(phdr);
        let flags = Self::ph_flag(phdr);
        phdr_table.add_row(Row::new(vec![
            Cell::new(&format!("{}", index)),
            name_cell,
            Cell::new(&flags),
            offsetx_cell(phdr.p_offset),
            addrx_cell(phdr.p_vaddr),
            memx_cell(phdr.p_paddr),
            sz_cell(phdr.p_filesz),
            memsz_cell(phdr.p_memsz),
            x_cell(phdr.p_align),
        ]));
    }

    fn print_note_header(
        fmt: &mut Buffer,
        index: usize,
        note: &elf::note::Note<'bytes>,
    ) -> Result<(), Error> {
        fmt_idx(fmt, index)?;
        write!(fmt, " ")?;
        fmt_str(fmt, note.name.trim_end_matches('\0'))?;
        write!(fmt, " type: {} ", note.type_to_str())?;
        for byte in note.desc {
            write!(fmt, "{:x}", byte)?;
        }
        writeln!(fmt).map_err(Into::into)
    }

    fn print_section_header(
        &self,
        index: usize,
        shdr: &elf::SectionHeader,
        shdr_table: &mut Table,
    ) -> Result<(), Error> {
        let name_cell = {
            let name = self
                .elf
                .shdr_strtab
                .get_at(shdr.sh_name)
                .unwrap_or("<error>");

            name_even_odd_cell(&self.args, index, name)
        };
        let flags_cell = Self::flags_cell(shdr)?;
        shdr_table.add_row(Row::new(vec![
            idx_cell(index),
            name_cell,
            Cell::new(section_header::sht_to_str(shdr.sh_type)).style_spec("r"),
            flags_cell,
            offsetx_cell(shdr.sh_offset),
            memx_cell(shdr.sh_addr),
            memsz_cell(shdr.sh_size),
            shndx_cell(
                &self.args,
                usize::try_from(shdr.sh_link)?,
                &self.elf.section_headers,
                &self.elf.shdr_strtab,
            ),
            x_cell(shdr.sh_entsize),
            x_cell(shdr.sh_addralign),
        ]));
        Ok(())
    }

    fn print_relocations(
        &self,
        fmt: &mut Buffer,
        writer: &BufferWriter,
        machine: u16,
    ) -> Result<(), Error> {
        let dyn_strtab = &self.elf.dynstrtab;
        let strtab = &self.elf.strtab;
        let syms = self.elf.syms.to_vec();
        let dynsyms = self.elf.dynsyms.to_vec();
        self.fmt_syms(fmt, writer, "Syms", &syms, strtab)?;
        self.fmt_syms(fmt, writer, "Dyn Syms", &dynsyms, dyn_strtab)?;

        fmt_header(fmt, "Dynamic Relas", self.elf.dynrelas.len())?;
        self.fmt_relocations(
            fmt,
            writer,
            &self.elf.dynrelas,
            &dynsyms,
            dyn_strtab,
            machine,
        )?;
        fmt_header(fmt, "Dynamic Rel", self.elf.dynrels.len())?;
        self.fmt_relocations(
            fmt,
            writer,
            &self.elf.dynrels,
            &dynsyms,
            dyn_strtab,
            machine,
        )?;
        fmt_header(fmt, "Plt Relocations", self.elf.pltrelocs.len())?;
        self.fmt_relocations(
            fmt,
            writer,
            &self.elf.pltrelocs,
            &dynsyms,
            dyn_strtab,
            machine,
        )?;

        let num_shdr_relocs = self
            .elf
            .shdr_relocs
            .iter()
            .map(|(_index, reloc_section)| reloc_section.len())
            .sum::<usize>();

        fmt_header(fmt, "Shdr Relocations", num_shdr_relocs)?;
        if num_shdr_relocs != 0 {
            for &(idx, ref relocs) in &self.elf.shdr_relocs {
                let mut name = None;
                if let Some(shdr) = self.elf.section_headers.get(idx) {
                    if let Some(shdr) = self.elf.section_headers.get(usize::try_from(shdr.sh_info)?)
                    {
                        name = self.elf.shdr_strtab.get_at(shdr.sh_name);
                    }
                }
                fmt_name_bold(fmt, &format!("  {}", name.unwrap_or("<error>")))?;
                writeln!(fmt, "({})", relocs.len())?;
                self.fmt_relocations(fmt, writer, relocs, &syms, strtab, machine)?;
            }
        }
        writeln!(fmt).map_err(Into::into)
    }

    fn print_dynamic_symbol(&self, fmt: &mut Buffer, dyn_sym: &elf::Dyn) -> Result<(), Error> {
        use dynamic::{
            tag_to_str, DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_GNU_HASH, DT_INIT,
            DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED, DT_PLTGOT, DT_PLTRELSZ, DT_RELA,
            DT_RELASZ, DT_RPATH, DT_STRSZ, DT_STRTAB, DT_SYMTAB, DT_VERNEED, DT_VERSYM,
        };

        fmt_cyan(fmt, &format!("{:>16} ", tag_to_str(dyn_sym.d_tag)))?;
        match dyn_sym.d_tag {
            DT_RPATH => {
                let val = usize::try_from(dyn_sym.d_val)?;
                let name = self.elf.dynstrtab.get_at(val).unwrap_or("<error>");
                fmt_string(fmt, &self.args, name)?;
            }

            DT_NEEDED => {
                let val = usize::try_from(dyn_sym.d_val)?;
                let name = self.elf.dynstrtab.get_at(val).unwrap_or("<error>");
                fmt_lib(fmt, name)?;
            }

            DT_INIT | DT_FINI | DT_INIT_ARRAY | DT_FINI_ARRAY | DT_GNU_HASH | DT_STRTAB
            | DT_SYMTAB | DT_PLTGOT | DT_JMPREL | DT_RELA | DT_VERNEED | DT_VERSYM => {
                fmt_addrx(fmt, dyn_sym.d_val)?;
            }

            DT_INIT_ARRAYSZ | DT_FINI_ARRAYSZ | DT_STRSZ | DT_PLTRELSZ | DT_RELASZ => {
                fmt_sz(fmt, dyn_sym.d_val)?;
            }

            _ => write!(fmt, "{:#x}", dyn_sym.d_val)?,
        }
        writeln!(fmt).map_err(Into::into)
    }

    pub fn print(&self) -> Result<(), Error> {
        let cc = if self.args.color || stdout().is_terminal() {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let header = &self.elf.header;
        let endianness = if self.elf.little_endian {
            "little-endian"
        } else {
            "big-endian"
        };
        let machine = header.e_machine;
        fmt_hdr(fmt, "ELF ")?;
        Self::kind(fmt, header)?;
        write!(fmt, " ")?;
        fmt_name_bold(fmt, header::machine_to_str(machine))?;
        write!(fmt, "-{} @ ", endianness)?;
        fmt_addrx(fmt, self.elf.entry)?;
        writeln!(fmt, ":")?;
        writeln!(fmt)?;
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
        writeln!(fmt)?;

        fmt_header(fmt, "ProgramHeaders", self.elf.program_headers.len())?;
        let mut phdr_table = new_table(
            row![b->"Idx", b->"Type", b->"Flags", b->"Offset", b->"Vaddr", b->"Paddr", b->"Filesz", b->"Memsz", b->"Align"],
        );
        for (i, phdr) in self.elf.program_headers.iter().enumerate() {
            Self::print_program_header(&mut phdr_table, i, phdr);
        }
        flush(fmt, &writer, &phdr_table, self.args.color)?;
        writeln!(fmt)?;

        if let Some(notes) = self.elf.iter_note_headers(self.bytes) {
            fmt_hdr(fmt, "Notes")?;
            writeln!(fmt)?;

            for (i, note) in notes.enumerate() {
                if let Ok(note) = note {
                    Self::print_note_header(fmt, i, &note)?;
                }
            }
            writeln!(fmt)?;
        }

        fmt_header(fmt, "SectionHeaders", self.elf.section_headers.len())?;
        let mut shdr_table = new_table(
            row![b->"Idx", b->"Name", br->"Type", b->"Flags", b->"Offset", b->"Addr", b->"Size", b->"Link", b->"Entsize", b->"Align"],
        );
        for (i, shdr) in self.elf.section_headers.iter().enumerate() {
            self.print_section_header(i, shdr, &mut shdr_table)?;
        }
        flush(fmt, &writer, &shdr_table, self.args.color)?;
        writeln!(fmt)?;

        self.print_relocations(fmt, &writer, machine)?;

        if let &Some(Dynamic { ref dyns, .. }) = &self.elf.dynamic {
            fmt_header(fmt, "Dynamic", dyns.len())?;
            for dyn_sym in dyns {
                self.print_dynamic_symbol(fmt, dyn_sym)?;
            }
        } else {
            writeln!(fmt, "Dynamic: None")?;
        }
        writeln!(fmt)?;
        writeln!(fmt)?;

        fmt_header(fmt, "Libraries", self.elf.libraries.len())?;
        for lib in &self.elf.libraries {
            fmt_lib(fmt, &format!("{:>16}", lib))?;
            writeln!(fmt)?;
        }
        writeln!(fmt)?;

        write!(fmt, "Soname: ")?;
        fmt_str_option(fmt, self.elf.soname)?;
        writeln!(fmt)?;
        write!(fmt, "Interpreter: ")?;
        fmt_str_option(fmt, self.elf.interpreter)?;
        writeln!(fmt)?;
        write!(fmt, "is_64: ")?;
        fmt_bool(fmt, self.elf.is_64)?;
        writeln!(fmt)?;
        write!(fmt, "is_lib: ")?;
        fmt_bool(fmt, self.elf.is_lib)?;
        writeln!(fmt)?;
        write!(fmt, "little_endian: ")?;
        fmt_bool(fmt, self.elf.little_endian)?;
        writeln!(fmt)?;
        write!(fmt, "entry: ")?;
        fmt_addr(fmt, self.elf.entry)?;
        writeln!(fmt)?;

        writer.print(fmt).map_err(Into::into)
    }
}
