use goblin::{container};
use mach;
use Opt;

use colored::Colorize;
use prettytable::cell::Cell;
use prettytable::row::Row;

use format::*;

pub struct Mach<'a>(pub mach::MachO<'a>, pub Opt);

impl<'a> ::std::fmt::Display for Mach<'a> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        use mach::header;
        use mach::load_command;
        use mach::exports::{Export};

        let mach = &self.0;
        let opt = &self.1;
        let header = &mach.header;
        let endianness = if header.is_little_endian() { "little-endian" } else { "big-endian" };
        let kind = {
            let typ_cell = header.filetype;
            let kind_str = header::filetype_to_str(typ_cell).reverse().bold();
            match typ_cell {
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
        let fmt_section = |fmt: &mut ::std::fmt::Formatter, i: usize, section: &load_command::Section | -> ::std::fmt::Result {
            if let Ok(name) = section.name() {
                write!(fmt,   "    {}: {:>16}", idx(i), string(opt, name))?;
                write!(fmt,   "    addr: {:>8} ",     addr(section.addr))?;
                write!(fmt,   "    size: {:>8} ",     sz(section.size))?;
                write!(fmt,   "    offset: {:>8} ",   off(section.offset as u64))?;
                write!(fmt,   "    align: {} ",    section.align)?;
                write!(fmt,   "    reloff: {} ",   off(section.reloff as u64))?;
                write!(fmt,   "    nreloc: {} ",   section.nreloc)?;
                write!(fmt,   "    flags: {:#10x} ",    section.flags)?;
                writeln!(fmt, "    data: {}",    section.data.len())
            } else {
                writeln!(fmt,   "    {}: {:>16}", idx(i), "BAD SECTION NAME")
            }
        };

        let fmt_sections = |fmt: &mut ::std::fmt::Formatter, sections: &[load_command::Section] | -> ::std::fmt::Result {
            for (i, section) in sections.into_iter().enumerate() {
                fmt_section(fmt, i, &section)?;
            }
            Ok(())
        };

        let segments = &*mach.segments;
        fmt_header(fmt, "Segments", segments.len())?;
        for (ref i, ref segment) in segments.into_iter().enumerate() {
            let name = segment.name().unwrap();
            let sections = &segment.sections().unwrap();
            writeln!(fmt, "  {}: {}",     (*i).to_string().yellow(), hdr_size(name, sections.len()).yellow())?;
            writeln!(fmt)?;
            if opt.pretty {
                let mut section_table = new_table(row![b->"Idx", b->"Name", b->"Addr", b->"Size", b->"Offset", b->"Align", b->"Reloff", b->"Nrelocs", b->"Flags"]);
                for (i, section) in sections.into_iter().enumerate() {

                    if let Ok(name) = section.name() {
                        section_table.add_row(Row::new(vec![
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
                section_table.print_tty(opt.color);

            } else {
                fmt_sections(fmt, sections)?;
            }
        }

        writeln!(fmt, "")?;

        let fmt_exports = |fmt: &mut ::std::fmt::Formatter, name: &str, syms: &[Export] | -> ::std::fmt::Result {
            fmt_header(fmt, name, syms.len())?;
            for sym in syms {
                write!(fmt, "{:>16} ", addr(sym.offset))?;
                write!(fmt, "{} ", string(opt, &sym.name))?;
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
            write!(fmt, "{} ", string(opt, &sym.name))?;
            write!(fmt, "({})", sz(sym.size as u64))?;
            writeln!(fmt, "-> {}", string(opt, sym.dylib).blue())?;
        }
        writeln!(fmt, "")?;

        fmt_header(fmt, "Libraries", mach.libs.len())?;
        for lib in &mach.libs[1..] {
            writeln!(fmt, "{:>16} ", string(opt, lib).blue())?;
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
