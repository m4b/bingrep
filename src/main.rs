extern crate atty;
extern crate termcolor;
extern crate goblin;
extern crate metagoblin;
extern crate hexplay;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate rustc_demangle;
extern crate scroll;
#[macro_use]
extern crate prettytable;
extern crate env_logger;

use goblin::{Hint, Object, elf, mach, archive};
use std::path::Path;
use std::fs::File;
use std::io::Read;

pub use goblin::error;
use structopt::StructOpt;

mod format;
mod format_elf;
use format_elf::Elf;
mod format_mach;
use format_mach::Mach;
mod format_archive;
use format_archive::Archive;
mod format_meta;
use format_meta::Meta;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "bingrep", about = "bingrep - grepping through binaries since 2017")]
pub struct Opt {
    #[structopt(long = "ranges", help = "Print a high level overview of the file offset ranges in this binary")]
    ranges: bool,

    #[structopt(long = "hex", help = "Print a colored and semantically tagged hex table")]
    hex: bool,

    #[structopt(short = "d", long = "debug", help = "Print debug version of parse results")]
    debug: bool,

    #[structopt(short = "t", long = "truncate", help = "Truncate string results to X characters", default_value = "32")]
    truncate: usize,

    #[structopt(long = "color", help = "Forces coloring, even in files and pipes")]
    color: bool,

    #[structopt(short = "s", long = "search", help = "Search for string")]
    search: Option<String>,

    #[structopt(short = "D", long = "demangle", help = "Apply Rust/C++ demangling")]
    demangle: bool,

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
        let object = Object::parse(&bytes)?;
        // we print the semantically tagged hex table
        if opt.hex || opt.ranges {
            let meta = Meta::new(&object, &bytes, opt.clone());
            if opt.hex {
                meta.print_hex()?;
            }
            else {
                meta.print_ranges()?;
            }
            return Ok(());
        }
        // otherwise we print the kind of object
        match object {
            Object::Elf(elf) => {
                if opt.debug {
                    println!("{:#?}", elf);
                } else {
                    let elf = Elf::new(elf, bytes.as_slice(), opt.clone());
                    if let Some(search) = opt.search {
                        elf.search(&search)?;
                    } else {
                        elf.print()?;
                    }
                }
            },
            Object::PE(pe) => {
                println!("pe: {:#?}", &pe);
            },
            Object::Mach(mach) => {
                match mach {
                    mach::Mach::Fat(multi) => {
                        for mach in &multi {
                            match mach {
                                Ok(binary) => {
                                    if opt.debug {
                                        println!("{:#?}", binary);
                                    } else {
                                        let mach = Mach(binary, opt.clone());
                                        mach.print()?;
                                    }
                                },
                                Err(err) => {
                                    println!("{}", err);
                                }
                            }
                        }
                    },
                    mach::Mach::Binary(binary) => {
                        if opt.debug {
                            println!("{:#?}", binary);
                        } else {
                            let mach = Mach(binary, opt.clone());
                            mach.print()?;
                        }
                    }
                }
            }
            Object::Archive(archive) => {
                if opt.debug {
                    println!("archive: {:#?}", &archive);
                } else {
                    let archive = Archive::new(archive, opt.clone());
                    archive.print()?;
                }
            },
            _ => unreachable!()
        }
    }
    Ok(())
}

pub fn main () {
    let opt = Opt::from_args();
    env_logger::init().unwrap();
    match run(opt) {
        Ok(()) => (),
        Err(err) => println!("{:#}", err)
    }
}
