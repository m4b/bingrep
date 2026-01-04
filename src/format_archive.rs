use anyhow::Error;
use metagoblin::archive;
use prettytable::{row, Cell, Row};

use crate::format::*;
use crate::Opt;

pub struct Archive<'archive> {
    archive: archive::Archive<'archive>,
    args: Opt,
}

impl<'archive> Archive<'archive> {
    pub fn new(archive: archive::Archive<'archive>, args: Opt) -> Self {
        Archive { archive, args }
    }

    pub fn print(&self) -> Result<(), Error> {
        let archive = &self.archive;
        let args = &self.args;
        let color = args.color;

        let mut table = new_table(row![b->"Size", b->"# Symbols", br->"Name"]);
        let mut symbol_table = new_table(row![br->"Symbol", rb->"Owner"]);
        for (membername, member, symbols) in archive.summarize() {
            table.add_row(Row::new(vec![
                sz_cell(u64::try_from(member.size())?),
                Cell::new(&format!("{}", symbols.len())),
                str_cell(membername).style_spec("brFr"),
            ]));

            for symbol in symbols {
                symbol_table.add_row(Row::new(vec![
                    string_cell(args, symbol),
                    str_cell(membername).style_spec("brFr"),
                ]));
            }
        }

        print_table_to_stdout(&table, color)?;
        println!();
        print_table_to_stdout(&symbol_table, color).map_err(Into::into)
    }
}
