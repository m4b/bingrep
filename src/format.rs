use prettytable::{format, Table};
use prettytable::row::Row;
use prettytable::cell::Cell;

use rustc_demangle;
use colored::{self, Colorize};

use Opt;

pub fn new_table(title: Row) -> Table {
    let sep = format::LineSeparator::new('-', '|', ' ', ' ');

    let format = format::FormatBuilder::new()
        .column_separator(' ')
        .borders(' ')
        .separators(&[], sep)
        .padding(1, 1)
        .build();

    let mut phdr_table = Table::new();
    phdr_table.set_titles(title);
    phdr_table.set_format(format);
    phdr_table
}

pub fn string_cell (opt: &Opt, s: &str) -> Cell {
    if s.is_empty() {
        Cell::new(&"")
    } else {
        Cell::new(&if opt.demangle {
            rustc_demangle::demangle(s).to_string()
        } else {
            s.into()
        }).style_spec("FYb")
    }
}

pub fn str_cell (s: &str) -> Cell {
    if s.is_empty() {
        Cell::new(&"")
    } else {
        Cell::new(s).style_spec("FYb")
    }
}

pub fn idx_cell (i: usize) -> Cell {
    let cell = Cell::new(&i.to_string());
    if i % 2 == 0 { cell.style_spec("FdBw") } else { cell.style_spec("FwBd") }
}

pub fn addr_cell (addr: u64) -> Cell {
    Cell::new(&format!("{:>16x} ", addr)).style_spec("Frr")
}

pub fn offsetx_cell (offset: u64) -> Cell {
    Cell::new(&format!("{:#x} ", offset)).style_spec("Fy")
}

pub fn addrx_cell (addr: u64) -> Cell {
    Cell::new(&format!("{:#x} ", addr)).style_spec("Fr")
}

pub fn memx_cell (maddr: u64) -> Cell {
    Cell::new(&format!("{:<#x} ", maddr)).style_spec("bFr")
}

pub fn sz_cell (size: u64) -> Cell {
    Cell::new(&format!("{:<#x} ", size)).style_spec("Fg")
}

pub fn memsz_cell (memsz: u64) -> Cell {
    Cell::new(&format!("{:<#x} ", memsz)).style_spec("bFg")
}

pub fn x_cell (num: u64) -> Cell {
    Cell::new(&format!("{:#x}", num))
}

pub fn bool_cell (b: bool) -> Cell {
    let cell = Cell::new(&format!("{} ", b));
    if b { cell.style_spec("bFg") } else { cell.style_spec("bFr") }
}

pub fn hdr(name: &str) -> colored::ColoredString {
    format!("{}", name).dimmed().white().underline()
}

pub fn hdr_size (name: &str, size: usize) -> colored::ColoredString {
    format!("{}({})", name, size).dimmed().white().underline()
}

pub fn fmt_header (fmt: &mut ::std::fmt::Formatter, name: &str, size: usize) -> ::std::fmt::Result {
    writeln!(fmt, "{}:\n", hdr_size(name, size))?;
    Ok(())
}

pub fn addr (addr: u64) -> colored::ColoredString {
    format!("{:x}",addr).red()
}

pub fn addrx (addr: u64) -> colored::ColoredString {
    format!("{:#x}",addr).red()
}

pub fn off (off: u64) -> colored::ColoredString {
    format!("{:#x}",off).yellow()
}

pub fn offs (off: isize) -> colored::ColoredString {
    format!("{:#x}",off).yellow()
}

pub fn string (opt: &Opt, s: &str) -> colored::ColoredString {
    if opt.demangle {
        rustc_demangle::demangle(s).to_string()
    } else {
        s.into()
    }.reverse().bold().yellow()
}

pub fn sz (sz: u64) -> colored::ColoredString {
    format!("{:#x}", sz).green()
}

pub fn idx (i: usize) -> colored::ColoredString {
    let index = format!("{:>4}", i);
    if i % 2 == 0 { index.white().on_black() } else { index.black().on_white() }
}
