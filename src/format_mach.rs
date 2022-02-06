use metagoblin::error;
use metagoblin::mach;
use metagoblin::mach::exports::Export;
use metagoblin::mach::header;
use metagoblin::mach::load_command;

use crate::Opt;

use prettytable::Cell;
use prettytable::Row;
use std::io::{self, Write};
use termcolor::Color::*;
use termcolor::*;

use crate::format::*;

pub struct Mach<'a>(pub mach::MachO<'a>, pub Opt);

impl<'a> Mach<'a> {
    pub fn print(&self) -> error::Result<()> {
        let mach = &self.0;
        let args = &self.1;

        let cc = if args.color || atty::is(atty::Stream::Stdout) {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let header = &mach.header;
        let endianness = if mach.little_endian {
            "little-endian"
        } else {
            "big-endian"
        };
        let machine = header.cputype;
        let kind = |fmt: &mut Buffer, header: &header::Header| {
            let typ_cell = header.filetype;
            let kind_str = header::filetype_to_str(typ_cell);
            match typ_cell {
                header::MH_OBJECT => fmt.set_color(
                    ::termcolor::ColorSpec::new()
                        .set_intense(true)
                        .set_bg(Some(Yellow))
                        .set_fg(Some(Black)),
                )?,
                header::MH_EXECUTE => fmt.set_color(
                    ::termcolor::ColorSpec::new()
                        .set_intense(true)
                        .set_bg(Some(Red))
                        .set_fg(Some(Black)),
                )?,
                header::MH_DYLIB => fmt.set_color(
                    ::termcolor::ColorSpec::new()
                        .set_intense(true)
                        .set_bg(Some(Yellow))
                        .set_fg(Some(Black)),
                )?,
                header::MH_DYLINKER => fmt.set_color(
                    ::termcolor::ColorSpec::new()
                        .set_intense(true)
                        .set_bg(Some(Yellow))
                        .set_fg(Some(Black)),
                )?,
                header::MH_DYLIB_STUB => fmt.set_color(
                    ::termcolor::ColorSpec::new()
                        .set_intense(true)
                        .set_bg(Some(Blue))
                        .set_fg(Some(Black)),
                )?,
                header::MH_DSYM => fmt.set_color(
                    ::termcolor::ColorSpec::new()
                        .set_intense(true)
                        .set_bg(Some(Green))
                        .set_fg(Some(Black)),
                )?,
                header::MH_CORE => fmt.set_color(
                    ::termcolor::ColorSpec::new()
                        .set_intense(true)
                        .set_bg(Some(White))
                        .set_fg(Some(Black)),
                )?,
                _ => (),
            }
            write!(fmt, "{}", kind_str)?;
            fmt.reset()
        };
        fmt_hdr(fmt, "Mach-o ")?;
        kind(fmt, &mach.header)?;
        write!(fmt, " ")?;
        fmt_name_bold(
            fmt,
            mach::constants::cputype::get_arch_name_from_types(machine, header.cpusubtype)
                .unwrap_or("None"),
        )?;
        write!(fmt, "-{} @ ", endianness)?;
        fmt_addrx(fmt, mach.entry as u64)?;
        writeln!(fmt, ":")?;
        writeln!(fmt)?;

        let lcs = &mach.load_commands;
        fmt_header(fmt, "LoadCommands", lcs.len())?;
        for (i, lc) in lcs.into_iter().enumerate() {
            fmt_idx(fmt, i)?;
            write!(fmt, " ")?;
            let name = load_command::cmd_to_str(lc.command.cmd());
            let name = &format!("{:.27}", name);
            match lc.command {
                load_command::CommandVariant::Segment32(_command) => {
                    fmt_name_color(fmt, name, Red)?
                }
                load_command::CommandVariant::Segment64(_command) => {
                    fmt_name_color(fmt, name, Red)?
                }
                load_command::CommandVariant::Symtab(_command) => {
                    fmt_name_color(fmt, name, Yellow)?
                }
                load_command::CommandVariant::Dysymtab(_command) => {
                    fmt_name_color(fmt, name, Green)?
                }
                load_command::CommandVariant::LoadDylinker(_command) => {
                    fmt_name_color(fmt, name, Yellow)?
                }
                load_command::CommandVariant::LoadDylib(_command)
                | load_command::CommandVariant::LoadUpwardDylib(_command)
                | load_command::CommandVariant::ReexportDylib(_command)
                | load_command::CommandVariant::LazyLoadDylib(_command) => {
                    fmt_name_color(fmt, name, Blue)?
                }
                load_command::CommandVariant::DyldInfo(_command)
                | load_command::CommandVariant::DyldInfoOnly(_command) => {
                    fmt_name_color(fmt, name, Cyan)?
                }
                load_command::CommandVariant::Unixthread(_command) => {
                    fmt_name_color(fmt, name, Red)?
                }
                load_command::CommandVariant::Main(_command) => fmt_name_color(fmt, name, Red)?,
                _ => fmt_name_bold(fmt, name)?,
            }
            writeln!(fmt)?;
        }

        writeln!(fmt)?;

        let segments = &mach.segments;
        fmt_header(fmt, "Segments", segments.len())?;
        for (ref _i, ref segment) in segments.into_iter().enumerate() {
            let name = segment.name().unwrap();
            let sections = &segment.sections().unwrap();
            let mut segment_table = new_table(row![b->"Segment", b->"# Sections"]);
            segment_table.add_row(Row::new(vec![
                str_cell(&name),
                Cell::new(&sections.len().to_string()),
            ]));
            flush(fmt, &writer, segment_table, args.color)?;

            let mut section_table = new_table(
                row![b->"", b->"Idx", b->"Name", b->"Addr", b->"Size", b->"Offset", b->"Align", b->"Reloff", b->"Nrelocs", b->"Flags"],
            );
            for (i, &(ref section, _)) in sections.into_iter().enumerate() {
                if let Ok(name) = section.name() {
                    section_table.add_row(Row::new(vec![
                        Cell::new(&format!("{:4}", "")), // filler
                        Cell::new(&i.to_string()),
                        Cell::new(name).style_spec("Fyb"),
                        addrx_cell(section.addr),
                        sz_cell(section.size),
                        offsetx_cell(section.offset as u64),
                        Cell::new(&format!("{}", section.align)),
                        offsetx_cell(section.reloff as u64),
                        Cell::new(&format!("{}", section.nreloc)),
                        Cell::new(&format!("{:#x}", section.flags)),
                    ]));
                } else {
                    section_table.add_row(Row::new(vec![
                        Cell::new(&i.to_string()),
                        Cell::new("BAD SECTION NAME"),
                    ]));
                }
            }
            flush(fmt, &writer, section_table, true)?;
            writeln!(fmt)?;
        }
        writeln!(fmt)?;

        let mut relocations: Vec<_> = Vec::new();
        let mut nrelocs = 0;
        let r = mach.relocations().unwrap();
        for (_i, relocs, section) in r.into_iter() {
            let section_name = section.name().unwrap();
            let segment_name = section.segname().unwrap();
            let mut rs = Vec::new();
            for reloc in relocs {
                let reloc = reloc.unwrap();
                nrelocs += 1;
                rs.push(reloc);
            }
            if !rs.is_empty() {
                relocations.push((segment_name.to_owned(), section_name.to_owned(), rs))
            };
        }
        // need this to print relocation references
        let symbols = mach.symbols().collect::<Vec<_>>();
        let sections = mach
            .segments
            .sections()
            .flat_map(|x| x)
            .map(|s| s.unwrap().0)
            .collect::<Vec<_>>();

        fmt_header(fmt, "Relocations", nrelocs)?;
        for (n1, n2, relocs) in relocations {
            let mut section_table = new_table(row![b->"Segment", b->"Section", b->"Count"]);
            section_table.add_row(Row::new(vec![
                str_cell(&n1),
                str_cell(&n2),
                Cell::new(&relocs.len().to_string()),
            ]));
            flush(fmt, &writer, section_table, args.color)?;
            let mut reloc_table = new_table(
                row![b->"", b->"Type", b->"Offset", b->"Length", b->"PIC", b->"Extern", b->"SymbolNum", b->"Symbol"],
            );
            for reloc in relocs {
                let idx = reloc.r_symbolnum();
                let name_cell = {
                    if reloc.is_extern() {
                        // FIXME: i cannot currently get this to compile without iterating and doing all this nonsense, otherwise move errors...
                        let mut maybe_name = None;
                        for (i, symbol) in symbols.iter().enumerate() {
                            match symbol {
                                &Ok((ref name, _)) => {
                                    let name: &str = name;
                                    if i == idx {
                                        maybe_name = Some(name);
                                    }
                                }
                                &Err(_) => (),
                            }
                        }
                        match maybe_name {
                            Some(name) => string_cell(&args, name),
                            None => cell("None").style_spec("b"),
                        }
                    // not extern so the symbol num should reference a section
                    } else {
                        let section = &sections[idx - 1 as usize];
                        let sectname = section.name()?;
                        let segname = section.segname()?;
                        cell(format!("{}.{}", segname, sectname)).style_spec("bi")
                    }
                };
                reloc_table.add_row(Row::new(vec![
                    Cell::new(&format!("{:4}", "")),
                    cell(reloc.to_str(machine)),
                    addrx_cell(reloc.r_address as u64),
                    cell(reloc.r_length()),
                    bool_cell(reloc.is_pic()),
                    bool_cell(reloc.is_extern()),
                    offsetx_cell(idx as u64),
                    name_cell,
                ]));
            }

            flush(fmt, &writer, reloc_table, args.color)?;
            writeln!(fmt)?;
        }
        writeln!(fmt)?;

        fmt_header(fmt, "Symbols", symbols.len())?;
        let mut symbol_table =
            new_table(row![b->"Offset", b->"Name", b->"Section", b->"Global", b->"Undefined"]);
        for (i, symbol) in symbols.into_iter().enumerate() {
            match symbol {
                Ok((name, symbol)) => {
                    let section_cell = if symbol.get_type() == mach::symbols::N_SECT {
                        // we subtract 1 because when N_SECT it is an ordinal, and hence indexing starts from 1
                        let section = &sections[symbol.n_sect - 1 as usize];
                        let sectname = section.name()?;
                        let segname = section.segname()?;
                        cell(format!("{}.{}", segname, sectname)).style_spec("b")
                    } else {
                        cell("None").style_spec("i")
                    };
                    symbol_table.add_row(Row::new(vec![
                        addrx_cell(symbol.n_value as u64),
                        string_cell(&args, name),
                        section_cell,
                        bool_cell(symbol.is_global()),
                        bool_cell(symbol.is_undefined()),
                    ]));
                }
                Err(e) => {
                    writeln!(fmt, "  {}: {}", i, e)?;
                }
            }
        }
        flush(fmt, &writer, symbol_table, args.color)?;
        writeln!(fmt)?;

        let fmt_exports = |fmt: &mut Buffer, name: &str, syms: &[Export]| -> io::Result<()> {
            fmt_header(fmt, name, syms.len())?;
            for sym in syms {
                fmt_addr_right(fmt, sym.offset)?;
                write!(fmt, " ")?;
                fmt_string(fmt, args, &sym.name)?;
                write!(fmt, " (")?;
                fmt_sz(fmt, sym.size as u64)?;
                writeln!(fmt, ")")?;
            }
            writeln!(fmt)
        };

        let exports = match mach.exports() {
            Ok(exports) => exports,
            Err(_) => Vec::new(),
        };
        fmt_exports(fmt, "Exports", &exports)?;

        let imports = match mach.imports() {
            Ok(imports) => imports,
            Err(_) => Vec::new(),
        };
        fmt_header(fmt, "Imports", imports.len())?;
        for sym in imports {
            fmt_addr_right(fmt, sym.offset)?;
            write!(fmt, " ")?;
            fmt_string(fmt, args, &sym.name)?;
            write!(fmt, " (")?;
            fmt_sz(fmt, sym.size as u64)?;
            write!(fmt, ")")?;
            write!(fmt, " -> ")?;
            fmt_lib(fmt, sym.dylib)?;
            writeln!(fmt)?;
        }
        writeln!(fmt)?;

        fmt_header(fmt, "Libraries", mach.libs.len() - 1)?;
        for lib in &mach.libs[1..] {
            fmt_lib_right(fmt, lib)?;
            writeln!(fmt)?;
        }
        writeln!(fmt)?;

        write!(fmt, "Name: ")?;
        fmt_str_option(fmt, &mach.name)?;
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
        fmt_addr(fmt, mach.entry as u64)?;
        writeln!(fmt)?;

        writer.print(fmt)?;
        Ok(())
    }
}
