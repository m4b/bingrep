use std::io::Write;

use anyhow::Result;
use metagoblin::mach;
use metagoblin::mach::exports::Export;
use metagoblin::mach::header;
use metagoblin::mach::load_command;
use prettytable::Table;
use prettytable::{Cell, Row};
use termcolor::Color::*;
use termcolor::{Buffer, BufferWriter, ColorChoice, ColorSpec, WriteColor};

use crate::format::*;
use crate::Opt;

pub struct Mach<'macho>(pub mach::MachO<'macho>, pub Opt);

impl<'macho> Mach<'macho> {
    fn color_spec(bg: termcolor::Color, fg: termcolor::Color) -> ColorSpec {
        let mut color = ColorSpec::new();
        color.set_intense(true).set_bg(Some(bg)).set_fg(Some(fg));
        color
    }

    fn kind(fmt: &mut Buffer, header: &header::Header) -> Result<()> {
        let cs = match header.filetype {
            header::MH_EXECUTE => Some(Self::color_spec(Red, Black)),
            header::MH_OBJECT | header::MH_DYLIB | header::MH_DYLINKER => {
                Some(Self::color_spec(Yellow, Black))
            }
            header::MH_DYLIB_STUB => Some(Self::color_spec(Blue, Black)),
            header::MH_DSYM => Some(Self::color_spec(Green, Black)),
            header::MH_CORE => Some(Self::color_spec(White, Black)),
            _ => None,
        };
        if let Some(cs) = cs {
            fmt.set_color(&cs)?;
        }
        write!(fmt, "{}", header::filetype_to_str(header.filetype))?;
        fmt.reset().map_err(Into::into)
    }

    fn print_load_command(
        fmt: &mut Buffer,
        index: usize,
        lc: &mach::load_command::LoadCommand,
    ) -> Result<()> {
        fmt_idx(fmt, index)?;
        write!(fmt, " ")?;
        let name = load_command::cmd_to_str(lc.command.cmd());
        let name = &format!("{:.27}", name);
        match lc.command {
            load_command::CommandVariant::Segment32(_)
            | load_command::CommandVariant::Segment64(_)
            | load_command::CommandVariant::Unixthread(_)
            | load_command::CommandVariant::Main(_) => fmt_name_color(fmt, name, Red)?,

            load_command::CommandVariant::Symtab(_)
            | load_command::CommandVariant::LoadDylinker(_) => fmt_name_color(fmt, name, Yellow)?,

            load_command::CommandVariant::Dysymtab(_) => fmt_name_color(fmt, name, Green)?,

            load_command::CommandVariant::LoadDylib(_)
            | load_command::CommandVariant::LoadUpwardDylib(_)
            | load_command::CommandVariant::ReexportDylib(_)
            | load_command::CommandVariant::LazyLoadDylib(_) => fmt_name_color(fmt, name, Blue)?,

            load_command::CommandVariant::DyldInfo(_)
            | load_command::CommandVariant::DyldInfoOnly(_) => fmt_name_color(fmt, name, Cyan)?,

            _ => fmt_name_bold(fmt, name)?,
        }
        writeln!(fmt).map_err(Into::into)
    }

    fn print_segment(
        &self,
        fmt: &mut Buffer,
        writer: &BufferWriter,
        segment: &mach::segment::Segment,
    ) -> Result<()> {
        let name = segment.name().unwrap();
        let sections = &segment.sections().unwrap();
        let mut segment_table = new_table(row![b->"Segment", b->"# Sections"]);
        segment_table.add_row(Row::new(vec![
            str_cell(name),
            Cell::new(&format!("{}", sections.len())),
        ]));
        flush(fmt, writer, &segment_table, self.1.color)?;

        let mut section_table = new_table(
            row![b->"", b->"Idx", b->"Name", b->"Addr", b->"Size", b->"Offset", b->"Align", b->"Reloff", b->"Nrelocs", b->"Flags"],
        );
        for (i, (section, _)) in sections.iter().enumerate() {
            if let Ok(name) = section.name() {
                section_table.add_row(Row::new(vec![
                    Cell::new(&format!("{:4}", "")), // filler
                    Cell::new(&format!("{}", i)),
                    Cell::new(name).style_spec("Fyb"),
                    addrx_cell(section.addr),
                    sz_cell(section.size),
                    offsetx_cell(u64::from(section.offset)),
                    Cell::new(&format!("{}", section.align)),
                    offsetx_cell(u64::from(section.reloff)),
                    Cell::new(&format!("{}", section.nreloc)),
                    Cell::new(&format!("{:#x}", section.flags)),
                ]));
            } else {
                section_table.add_row(Row::new(vec![
                    Cell::new(&format!("{}", i)),
                    Cell::new("BAD SECTION NAME"),
                ]));
            }
        }
        flush(fmt, writer, &section_table, true)?;
        writeln!(fmt).map_err(Into::into)
    }

    fn print_relocation(
        &self,
        symbols: &[metagoblin::error::Result<(&str, mach::symbols::Nlist)>],
        sections: &[mach::segment::Section],
        machine: u32,
        reloc: mach::relocation::RelocationInfo,
        reloc_table: &mut Table,
    ) -> Result<()> {
        let idx = reloc.r_symbolnum();
        let name_cell = {
            if reloc.is_extern() {
                // FIXME: i cannot currently get this to compile without iterating and doing all this nonsense, otherwise move errors...
                let mut maybe_name: Option<&str> = None;
                for (i, symbol) in symbols.iter().enumerate() {
                    if let Ok((name, _)) = *symbol {
                        if i == idx {
                            maybe_name = Some(name);
                        }
                    }
                }
                match maybe_name {
                    Some(name) => string_cell(&self.1, name),
                    None => cell("None").style_spec("b"),
                }
            // not extern so the symbol num should reference a section
            } else {
                let (section_name, segment_name) = if let Some(section) = sections.get(idx - 1) {
                    (section.name()?, section.segname()?)
                } else {
                    ("<error>", "<error>")
                };
                cell(format!("{}.{}", segment_name, section_name)).style_spec("bi")
            }
        };

        reloc_table.add_row(Row::new(vec![
            Cell::new(&format!("{:4}", "")),
            cell(reloc.to_str(machine)),
            addrx_cell(u64::try_from(reloc.r_address)?),
            cell(format!("{}", reloc.r_length())),
            bool_cell(reloc.is_pic()),
            bool_cell(reloc.is_extern()),
            offsetx_cell(u64::try_from(idx)?),
            name_cell,
        ]));
        Ok(())
    }

    fn print_symbol(
        &self,
        name: &str,
        symbol: &mach::symbols::Nlist,
        sections: &[mach::segment::Section],
        symbol_table: &mut Table,
    ) -> Result<()> {
        let section_cell = if symbol.get_type() == mach::symbols::N_SECT {
            // we subtract 1 because when N_SECT it is an ordinal, and hence indexing starts from 1
            let (section_name, segment_name) =
                if let Some(section) = sections.get(symbol.n_sect - 1) {
                    (section.name()?, section.segname()?)
                } else {
                    ("<error>", "<error>")
                };

            cell(format!("{}.{}", segment_name, section_name)).style_spec("b")
        } else {
            cell("None").style_spec("i")
        };
        symbol_table.add_row(Row::new(vec![
            addrx_cell(symbol.n_value),
            string_cell(&self.1, name),
            section_cell,
            bool_cell(symbol.is_global()),
            bool_cell(symbol.is_undefined()),
        ]));
        Ok(())
    }

    fn print_symbols(
        &self,
        fmt: &mut Buffer,
        writer: &BufferWriter,
        symbols: &[metagoblin::error::Result<(&str, mach::symbols::Nlist)>],
        sections: &[mach::segment::Section],
    ) -> Result<()> {
        fmt_header(fmt, "Symbols", symbols.len())?;
        let mut symbol_table =
            new_table(row![b->"Offset", b->"Name", b->"Section", b->"Global", b->"Undefined"]);
        for (i, symbol) in symbols.iter().enumerate() {
            match symbol {
                Ok((name, symbol)) => {
                    self.print_symbol(name, symbol, sections, &mut symbol_table)?;
                }
                Err(e) => writeln!(fmt, "  {}: {}", i, e)?,
            }
        }
        flush(fmt, writer, &symbol_table, self.1.color)?;
        writeln!(fmt).map_err(Into::into)
    }

    fn fmt_exports(&self, fmt: &mut Buffer, name: &str, syms: &[Export]) -> Result<()> {
        fmt_header(fmt, name, syms.len())?;
        for sym in syms {
            fmt_addr_right(fmt, sym.offset)?;
            write!(fmt, " ")?;
            fmt_string(fmt, &self.1, &sym.name)?;
            write!(fmt, " (")?;
            fmt_sz(fmt, u64::try_from(sym.size)?)?;
            writeln!(fmt, ")")?;
        }
        writeln!(fmt).map_err(Into::into)
    }

    fn print_imports(&self, fmt: &mut Buffer, imports: &[mach::imports::Import]) -> Result<()> {
        fmt_header(fmt, "Imports", imports.len())?;
        for sym in imports {
            fmt_addr_right(fmt, sym.offset)?;
            write!(fmt, " ")?;
            fmt_string(fmt, &self.1, sym.name)?;
            write!(fmt, " (")?;
            fmt_sz(fmt, u64::try_from(sym.size)?)?;
            write!(fmt, ")")?;
            write!(fmt, " -> ")?;
            fmt_lib(fmt, sym.dylib)?;
            writeln!(fmt)?;
        }
        writeln!(fmt).map_err(Into::into)
    }

    fn collect_relocations(
        mach: &mach::MachO,
    ) -> (
        Vec<(String, String, Vec<mach::relocation::RelocationInfo>)>,
        usize,
    ) {
        let mut relocations: Vec<_> = Vec::new();
        let mut nrelocs = 0;
        let r = mach.relocations().unwrap();
        for (_i, relocs, section) in r {
            let section_name = section.name().unwrap();
            let segment_name = section.segname().unwrap();
            let mut rs = Vec::new();
            for reloc in relocs {
                let reloc = reloc.unwrap();
                nrelocs += 1;
                rs.push(reloc);
            }
            if !rs.is_empty() {
                relocations.push((segment_name.to_owned(), section_name.to_owned(), rs));
            };
        }
        (relocations, nrelocs)
    }

    pub fn print(&self) -> Result<()> {
        let mach = &self.0;

        let cc = if self.1.color || atty::is(atty::Stream::Stdout) {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let endianness = if mach.little_endian {
            "little-endian"
        } else {
            "big-endian"
        };

        fmt_hdr(fmt, "Mach-o ")?;
        Self::kind(fmt, &mach.header)?;
        write!(fmt, " ")?;
        let arch_name = mach::constants::cputype::get_arch_name_from_types(
            mach.header.cputype,
            mach.header.cpusubtype,
        )
        .unwrap_or("None");
        fmt_name_bold(fmt, arch_name)?;
        write!(fmt, "-{} @ ", endianness)?;
        fmt_addrx(fmt, mach.entry)?;
        writeln!(fmt, ":")?;
        writeln!(fmt)?;

        fmt_header(fmt, "LoadCommands", mach.load_commands.len())?;
        for (i, lc) in mach.load_commands.iter().enumerate() {
            Self::print_load_command(fmt, i, lc)?;
        }
        writeln!(fmt)?;

        fmt_header(fmt, "Segments", mach.segments.len())?;
        for segment in &mach.segments {
            self.print_segment(fmt, &writer, segment)?;
        }
        writeln!(fmt)?;

        let (relocations, nrelocs) = Self::collect_relocations(mach);

        // need this to print relocation references
        let symbols = mach.symbols().collect::<Vec<_>>();
        let sections = mach
            .segments
            .sections()
            .flatten()
            .map(|s| s.unwrap().0)
            .collect::<Vec<_>>();

        fmt_header(fmt, "Relocations", nrelocs)?;
        for (n1, n2, relocs) in relocations {
            let mut section_table = new_table(row![b->"Segment", b->"Section", b->"Count"]);
            section_table.add_row(Row::new(vec![
                str_cell(n1.as_ref()),
                str_cell(n2.as_ref()),
                Cell::new(&format!("{}", relocs.len())),
            ]));
            flush(fmt, &writer, &section_table, self.1.color)?;
            let mut reloc_table = new_table(
                row![b->"", b->"Type", b->"Offset", b->"Length", b->"PIC", b->"Extern", b->"SymbolNum", b->"Symbol"],
            );
            for reloc in relocs {
                self.print_relocation(
                    &symbols,
                    &sections,
                    mach.header.cputype,
                    reloc,
                    &mut reloc_table,
                )?;
            }

            flush(fmt, &writer, &reloc_table, self.1.color)?;
            writeln!(fmt)?;
        }
        writeln!(fmt)?;

        self.print_symbols(fmt, &writer, &symbols, &sections)?;

        let exports = mach.exports().ok().unwrap_or_default();
        self.fmt_exports(fmt, "Exports", &exports)?;

        let imports = mach.imports().ok().unwrap_or_default();
        self.print_imports(fmt, &imports)?;

        fmt_header(fmt, "Libraries", mach.libs.len() - 1)?;
        for &lib in mach.libs.iter().skip(1) {
            fmt_lib_right(fmt, lib)?;
            writeln!(fmt)?;
        }
        writeln!(fmt)?;

        write!(fmt, "Name: ")?;
        fmt_str_option(fmt, mach.name)?;
        writeln!(fmt)?;
        write!(fmt, "is_64: ")?;
        fmt_bool(fmt, mach.is_64)?;
        writeln!(fmt)?;
        write!(fmt, "is_lib: ")?;
        fmt_bool(fmt, mach.header.filetype == header::MH_DYLIB)?;
        writeln!(fmt)?;
        write!(fmt, "little_endian: ")?;
        fmt_bool(fmt, mach.little_endian)?;
        writeln!(fmt)?;
        write!(fmt, "entry: ")?;
        fmt_addr(fmt, mach.entry)?;
        writeln!(fmt)?;

        writer.print(fmt)?;
        Ok(())
    }
}
