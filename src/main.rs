extern crate goblin;
extern crate colored;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate rustc_demangle;
extern crate scroll;
#[macro_use]
extern crate prettytable;
extern crate term;

use goblin::{error, Hint, pe, elf, mach, archive};
use std::path::Path;
use std::fs::File;
use std::io::Read;

use structopt::StructOpt;

mod format;
mod format_elf;
use format_elf::Elf;
mod format_mach;
use format_mach::Mach;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "bingrep", about = "bingrep - grepping through binaries since 2017")]
pub struct Opt {

    /// A flag, true if used in the command line.
    #[structopt(short = "d", long = "debug", help = "Print debug version of parse results")]
    debug: bool,

    /// Whether to use pretty tables
    #[structopt(short = "p", long = "pretty", help = "Use pretty tables")]
    pretty: bool,

    /// Force coloring
    #[structopt(long = "color", help = "Color")]
    color: bool,

    ///
    #[structopt(short = "s", long = "search", help = "Search for string")]
    search: Option<String>,

    /// A flag, true if used in the command line.
    #[structopt(short = "D", long = "demangle", help = "Apply Rust/C++ demangling")]
    demangle: bool,

    /// Needed parameter, the first on the command line.
    #[structopt(help = "Binary file")]
    input: String,
}

fn run (opt: Opt) -> error::Result<()> {
    let path = Path::new(&opt.input);
    let mut fd = File::open(path)?;
    let peek = goblin::peek(&mut fd)?;
    if let Hint::Unknown(magic) = peek {
        println!("unknown magic: {:#x}", magic)
    } else {
        let bytes = { let mut v = Vec::new(); fd.read_to_end(&mut v)?; v };
        match peek {
            Hint::Elf(_) => {
                let elf = elf::Elf::parse(&bytes)?;
                if opt.debug {
                    println!("{:#?}", elf);
                } else {
                    println!("{}", Elf::new(elf, bytes.as_slice(), opt.clone()));
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
                                        println!("{}", Mach(binary, opt.clone()));
                                    },
                                    Err(err) => {
                                        println!("{}", err);
                                    }
                                }
                            }
                        },
                        mach::Mach::Binary(binary) => {
                            println!("{}", Mach(binary, opt.clone()));
                        }
                    }
                }
            }
            Hint::Mach(_) => {
                let mach = mach::MachO::parse(&bytes, 0)?;
                if opt.debug {
                    println!("{:#?}", mach);
                } else {
                    println!("{}", Mach(mach, opt.clone()));
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
