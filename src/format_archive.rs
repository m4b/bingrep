use archive;

use Opt;

//use colored::Colorize;
use prettytable::cell::Cell;
use prettytable::row::Row;

use format::*;

use std::io;

pub struct Archive<'a> {
    archive: archive::Archive<'a>,
    args: Opt
}

impl<'a> Archive<'a> {
    pub fn new(archive: archive::Archive<'a>, args: Opt) -> Self {
        Archive {archive, args}
    }
    pub fn print(&self) -> io::Result<()> {
        let archive = &self.archive;
        let args = &self.args;
        let color = args.color;

        let mut table = new_table(row![b->"Size", b->"# Symbols", br->"Name"]);
        let mut symbol_table = new_table(row![br->"Symbol", rb->"Owner"]);
        for (membername, member, symbols) in archive.summarize() {
            table.add_row(Row::new(vec![
                sz_cell(member.size() as u64),
                Cell::new(&symbols.len().to_string()),
                str_cell(&membername).style_spec("brFr"),
            ]));

            for symbol in symbols {
                symbol_table.add_row(Row::new(vec![
                    string_cell(&args, symbol),
                    str_cell(membername).style_spec("brFr"),
                ]));
            }
        }

        table.print_tty(color);
        println!();
        symbol_table.print_tty(color);
        Ok(())
    }
}
