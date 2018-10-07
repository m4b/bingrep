use prettytable::{format, Table};
use prettytable::Row;
use prettytable::Cell;
use cpp_demangle;

use rustc_demangle;
use termcolor::{Buffer, BufferWriter, WriteColor};
use std::io::Write;
use termcolor::Color::*;

use Opt;

macro_rules! color_bold {
    ($fmt:ident, $color:ident, $str:expr) => ({
    $fmt.set_color(::termcolor::ColorSpec::new().set_bold(true).set_fg(Some($color)))?;
    write!($fmt, "{}", $str)?;
    $fmt.reset()
    })
}

macro_rules! color {
    ($fmt:ident, $color:ident, $str:expr) => ({
        $fmt.set_color(::termcolor::ColorSpec::new().set_fg(Some($color)))?;
        write!($fmt, "{}", $str)?;
        $fmt.reset()
    })
}

macro_rules! color_dim {
    ($fmt:ident, $color:ident, $str:expr) => ({
        $fmt.set_color(::termcolor::ColorSpec::new().set_fg(Some($color)).set_intense(false))?;
        write!($fmt, "{}", $str)?;
        $fmt.reset()
    })
}

fn union_demangle(s: &str) -> String {
    match rustc_demangle::try_demangle(s) {
        Ok(demangled) => demangled.to_string(),
        Err(_) => {
            match cpp_demangle::Symbol::new(s) {
                Ok(sym) => sym.to_string(),
                Err(_) => s.to_string(),
            }
        }
    }
}

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

pub fn truncate(opt: &Opt, string: &str) -> String {
    if string.is_empty() {
        return string.to_string();
    }
    let mut s = if opt.demangle {
        union_demangle(string)
    } else {
        string.into()
    };
    if s.len() > opt.truncate { s.truncate(opt.truncate); s += "…"; }
    s
}

pub fn string_cell (opt: &Opt, string: &str) -> Cell {
    if string.is_empty() {
        Cell::new(&"")
    } else {
        let s = truncate(opt, string);
        Cell::new(&s).style_spec("FYb")
    }
}

pub fn str_cell (s: &str) -> Cell {
    if s.is_empty() {
        Cell::new(&"")
    } else {
        Cell::new(s).style_spec("FYb")
    }
}

fn even_odd_cell (i: usize, cell: Cell) -> Cell {
    if i % 2 == 0 { cell.style_spec("FdBw") } else { cell.style_spec("FwBd") }
}

pub fn idx_cell (i: usize) -> Cell {
    let cell = Cell::new(&i.to_string());
    even_odd_cell(i, cell)
}

pub fn name_even_odd_cell (opt: &Opt, i: usize, name: &str) -> Cell {
    even_odd_cell(i, string_cell(opt, name))
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

pub fn cell<T: ToString> (n: T) -> Cell {
    Cell::new(&format!("{}", n.to_string()))
}

pub fn bool_cell (b: bool) -> Cell {
    let cell = Cell::new(&format!("{} ", b));
    if b { cell.style_spec("bFg") } else { cell.style_spec("bFr") }
}

pub fn fmt_hdr(fmt: &mut Buffer, name: &str) -> ::std::io::Result<()> {
    color!(fmt, White, name)
}

pub fn fmt_hdr_size (fmt: &mut Buffer, name: &str, size: usize) -> ::std::io::Result<()> {
    color_dim!(fmt, White, format!("{}({})", name, size))
}

pub fn fmt_header (fmt: &mut Buffer, name: &str, size: usize) -> ::std::io::Result<()> {
    fmt_hdr_size(fmt, name, size)?;
    writeln!(fmt, ":")?;
    Ok(())
}

pub fn fmt_addr (fmt: &mut Buffer, addr: u64) -> ::std::io::Result<()> {
    color!(fmt, Red, format!("{:x}",addr))
}

pub fn fmt_addr_right (fmt: &mut Buffer, addr: u64) -> ::std::io::Result<()> {
    color!(fmt, Red, format!("{:>16x}",addr))
}

pub fn fmt_addrx (fmt: &mut Buffer, addr: u64) -> ::std::io::Result<()> {
    color!(fmt, Red, format!("{:#x}",addr))
}

pub fn fmt_isize (fmt: &mut Buffer, i: isize) -> ::std::io::Result<()> {
    color!(fmt, Red, format!("{}",i))
}

pub fn fmt_off (fmt: &mut Buffer, off: u64) -> ::std::io::Result<()> {
    color!(fmt, Yellow, format!("{:#x}",off))
}

pub fn fmt_string (fmt: &mut Buffer, opt: &Opt, s: &str) -> ::std::io::Result<()> {
    color_bold!(fmt, Yellow, if opt.demangle {
        union_demangle(s)
    } else {
        s.into()
    })
}

pub fn fmt_str_option(fmt: &mut Buffer, s: &Option<&str>) -> ::std::io::Result<()> {
    if let &Some(ref s) = s{
        fmt_str(fmt, s)
    } else {
        fmt_name_dim(fmt, "None")
    }
}

pub fn fmt_str (fmt: &mut Buffer, s: &str) -> ::std::io::Result<()> {
    color_bold!(fmt, Yellow, s)
}

pub fn fmt_bool (fmt: &mut Buffer, b: bool) -> ::std::io::Result<()> {
    if b {
        fmt.set_color(::termcolor::ColorSpec::new().set_bold(true).set_intense(true).set_fg(Some(Green)))?;
    } else {
        fmt.set_color(::termcolor::ColorSpec::new().set_bold(true).set_intense(true).set_fg(Some(Red)))?;
    }
    write!(fmt, "{}", b)?;
    fmt.reset()
}

pub fn fmt_name_bold (fmt: &mut Buffer, s: &str) -> ::std::io::Result<()> {
    color_bold!(fmt, White, s)
}

pub fn fmt_name_dim (fmt: &mut Buffer, s: &str) -> ::std::io::Result<()> {
    color_dim!(fmt, White, s)
}

pub fn fmt_name_color(fmt: &mut Buffer, s: &str, color: ::termcolor::Color) -> ::std::io::Result<()> {
    color!(fmt, color, s)
}

pub fn fmt_lib (fmt: &mut Buffer, s: &str) -> ::std::io::Result<()> {
    color_bold!(fmt, Blue, s)
}

pub fn fmt_lib_right (fmt: &mut Buffer, s: &str) -> ::std::io::Result<()> {
    color_bold!(fmt, Blue, format!("{:>16}",s))
}

pub fn fmt_cyan (fmt: &mut Buffer, s: &str) -> ::std::io::Result<()> {
    color!(fmt, Cyan, s)
}

pub fn fmt_sz (fmt: &mut Buffer, fmt_sz: u64) -> ::std::io::Result<()> {
    color!(fmt, Green, format!("{:#x}", fmt_sz))
}

pub fn fmt_idx (fmt: &mut Buffer, i: usize) -> ::std::io::Result<()> {
    let index = format!("{:>4}", i);
    if i % 2 == 0 {
        fmt.set_color(::termcolor::ColorSpec::new().set_fg(Some(White)))?;
    } else {
        fmt.set_color(::termcolor::ColorSpec::new().set_bg(Some(White)).set_fg(Some(Black)))?;
    }
    write!(fmt, "{}", index)?;
    fmt.reset()
}

pub fn flush(fmt: &mut Buffer, writer: &BufferWriter, table: Table, color: bool) -> ::std::io::Result<()> {
    writer.print(fmt)?;
    fmt.clear();
    table.print_tty(color);
    Ok(())
}
