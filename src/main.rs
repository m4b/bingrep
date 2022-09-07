#[macro_use]
extern crate prettytable;

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Error;
use clap::Parser;
use metagoblin::{elf, mach, Hint, Object};

mod format;
mod format_elf;
use crate::format_elf::Elf;
mod format_mach;
use crate::format_mach::Mach;
mod format_archive;
use crate::format_archive::Archive;
mod format_meta;
use crate::format_meta::Meta;
mod format_pe;
use crate::format_pe::{is_pe_object_file_header, PEObjectFile, PortableExecutable};

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "bingrep",
    about = "bingrep - grepping through binaries since 2017"
)]
pub struct Opt {
    #[clap(
        long = "extract",
        help = "Extract from an archive the object file which contains the given symbol"
    )]
    extract: Option<String>,

    #[clap(
        long = "ranges",
        help = "Print a high level overview of the file offset ranges in this binary"
    )]
    ranges: bool,

    #[clap(
        long = "hex",
        help = "Print a colored and semantically tagged hex table"
    )]
    hex: bool,

    #[clap(
        short = 'd',
        long = "debug",
        help = "Print debug version of parse results"
    )]
    debug: bool,

    #[clap(
        short = 't',
        long = "truncate",
        help = "Truncate string results to X characters",
        default_value = "2048"
    )]
    truncate: usize,

    #[clap(long = "color", help = "Forces coloring, even in files and pipes")]
    color: bool,

    #[clap(short = 's', long = "search", help = "Search for string")]
    search: Option<String>,

    #[clap(short = 'D', long = "demangle", help = "Apply Rust/C++ demangling")]
    demangle: bool,

    #[clap(help = "Binary file")]
    input: String,
}

fn run(opt: Opt) -> Result<(), Error> {
    let bytes = std::fs::read(&opt.input)
        .map_err(|err| anyhow::anyhow!("Problem reading file {:?}: {}", opt.input, err))?;

    let prefix_bytes = <&[u8; 16]>::try_from(&bytes[..16])?;
    let peek = metagoblin::peek_bytes(prefix_bytes)?;
    if let Hint::Unknown(magic) = peek {
        if is_pe_object_file_header(&bytes) {
            let coff = metagoblin::pe::Coff::parse(&bytes)?;
            if opt.debug {
                println!("{:#?}", coff);
            } else {
                let coff = PEObjectFile::new(coff, bytes.as_slice(), opt.clone());
                if let Some(search) = opt.search {
                    coff.search(&search)?;
                } else {
                    coff.print()?;
                }
            }
        } else {
            return Err(anyhow::anyhow!("Unknown magic: {:#x}", magic));
        }
    } else {
        let object = Object::parse(&bytes)?;
        // we print the semantically tagged hex table
        if opt.hex || opt.ranges {
            let meta = Meta::new(&object, &bytes, opt.clone());
            if opt.hex {
                meta.print_hex()?;
            } else {
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
            }
            Object::PE(pe) => {
                if opt.debug {
                    println!("{:#?}", &pe);
                } else {
                    let pe = PortableExecutable::new(pe, bytes.as_slice(), opt.clone());
                    if let Some(search) = opt.search {
                        pe.search(&search)?;
                    } else {
                        pe.print()?;
                    }
                }
            }
            Object::Mach(mach) => match mach {
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
                            }
                            Err(err) => {
                                println!("{}", err);
                            }
                        }
                    }
                }
                mach::Mach::Binary(binary) => {
                    if opt.debug {
                        println!("{:#?}", binary);
                    } else {
                        let mach = Mach(binary, opt.clone());
                        mach.print()?;
                    }
                }
            },
            Object::Archive(archive) => {
                if let Some(symbol) = opt.extract {
                    if let Some(member) = archive.member_of_symbol(&symbol) {
                        let bytes = archive.extract(member, &bytes)?;
                        let mut file = File::create(Path::new(member))?;
                        file.write_all(bytes)?;
                    } else {
                        return Err(anyhow::anyhow!("No member contains {:?}", symbol));
                    }
                } else if opt.debug {
                    println!("archive: {:#?}", &archive);
                } else {
                    let archive = Archive::new(archive, opt.clone());
                    archive.print()?;
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

pub fn main() {
    let opt = Opt::parse();
    env_logger::init();
    match run(opt) {
        Ok(()) => (),
        Err(err) => {
            // We assume broken pipe errors are only due to standard output or
            // standard error being closed from the other side of the pipe.
            // These errors are usually ignored in command line utilities,
            // so they are not reported here beyond the exit status.
            let io_kind = err
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind);

            if io_kind != Some(std::io::ErrorKind::BrokenPipe) {
                eprintln!("{}", err);
            }
            std::process::exit(1);
        }
    }
}
