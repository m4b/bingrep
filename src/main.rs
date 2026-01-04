mod format;
mod format_archive;
mod format_elf;
mod format_mach;
mod format_meta;
mod format_pe;

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Error;
use clap::Parser;
use metagoblin::{Hint, Object, archive, elf, mach, pe};

use crate::format_archive::Archive;
use crate::format_elf::Elf;
use crate::format_mach::Mach;
use crate::format_meta::Meta;
use crate::format_pe::{PEObjectFile, PortableExecutable, is_pe_object_file_header};

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "bingrep",
    about = "bingrep - grepping through binaries since 2017",
    version
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

fn parse_pe_coff_object_file(opt: Opt, bytes: &[u8]) -> Result<(), Error> {
    let coff = metagoblin::pe::Coff::parse(bytes)?;
    if opt.debug {
        println!("{:#?}", coff);
        return Ok(());
    }

    let search = opt.search.clone();
    let coff = PEObjectFile::new(coff, bytes, opt);
    if let Some(search) = search {
        coff.search(&search)
    } else {
        coff.print()
    }
}

fn parse_elf_file(opt: Opt, bytes: &[u8], elf: elf::Elf) -> Result<(), Error> {
    if opt.debug {
        println!("{:#?}", elf);
        return Ok(());
    }

    let search = opt.search.clone();
    let elf = Elf::new(elf, bytes, opt);
    if let Some(search) = search {
        elf.search(&search)
    } else {
        elf.print()
    }
}

fn parse_pe_file(opt: Opt, bytes: &[u8], pe: pe::PE) -> Result<(), Error> {
    if opt.debug {
        println!("{:#?}", &pe);
        return Ok(());
    }

    let search = opt.search.clone();
    let pe = PortableExecutable::new(pe, bytes, opt);
    if let Some(search) = search {
        pe.search(&search)
    } else {
        pe.print()
    }
}

fn parse_mac_binary_file(opt: Opt, binary: mach::MachO) -> Result<(), Error> {
    if opt.debug {
        println!("{:#?}", binary);
    } else {
        let mach = Mach(binary, opt);
        mach.print()?;
    }
    Ok(())
}

fn parse_mac_file(opt: Opt, bytes: &[u8], mach: mach::Mach) -> Result<(), Error> {
    match mach {
        mach::Mach::Fat(multi) => {
            for mach in &multi {
                match mach {
                    Ok(res) => match res {
                        mach::SingleArch::MachO(binary) => {
                            parse_mac_binary_file(opt.clone(), binary)?
                        }
                        mach::SingleArch::Archive(archive) => {
                            parse_archive_file(opt.clone(), bytes, archive)?
                        }
                    },
                    Err(err) => println!("{}", err),
                }
            }
            Ok(())
        }
        mach::Mach::Binary(binary) => parse_mac_binary_file(opt, binary),
    }
}

fn parse_archive_file(opt: Opt, bytes: &[u8], archive: archive::Archive) -> Result<(), Error> {
    if let Some(symbol) = opt.extract {
        if let Some(member) = archive.member_of_symbol(&symbol) {
            let bytes = archive.extract(member, bytes)?;
            let mut file = File::create(Path::new(member))?;
            file.write_all(bytes).map_err(Into::into)
        } else {
            Err(anyhow::anyhow!("No member contains {:?}", symbol))
        }
    } else if opt.debug {
        println!("archive: {:#?}", &archive);
        Ok(())
    } else {
        let archive = Archive::new(archive, opt);
        archive.print().map_err(Into::into)
    }
}

fn run(opt: Opt) -> Result<(), Error> {
    let bytes = std::fs::read(&opt.input)
        .map_err(|err| anyhow::anyhow!("Problem reading file {:?}: {}", opt.input, err))?;

    let prefix_bytes = bytes.get(..16).ok_or_else(|| {
        anyhow::anyhow!(
            "File size is too small {:?}: {} bytes",
            opt.input,
            bytes.len()
        )
    })?;
    let prefix_bytes = <&[u8; 16]>::try_from(prefix_bytes)?;

    let peek = metagoblin::peek_bytes(prefix_bytes)?;
    if let Hint::Unknown(magic) = peek {
        if is_pe_object_file_header(&bytes) {
            return parse_pe_coff_object_file(opt, &bytes);
        }

        return Err(anyhow::anyhow!("Unknown magic: {:#x}", magic));
    }

    let object = Object::parse(&bytes)?;

    // we print the semantically tagged hex table
    if opt.hex || opt.ranges {
        let hex = opt.hex;
        let meta = Meta::new(&object, &bytes, opt);
        if hex {
            meta.print_hex()?;
        } else {
            meta.print_ranges()?;
        }
        return Ok(());
    }

    // otherwise we print the kind of object
    match object {
        Object::Elf(elf) => parse_elf_file(opt, &bytes, elf),
        Object::PE(pe) => parse_pe_file(opt, &bytes, pe),
        Object::COFF(coff) => {
            // TODO: print/format coff
            println!("{coff:?}");
            Ok(())
        }
        Object::Mach(mach) => parse_mac_file(opt, &bytes, mach),
        Object::Archive(archive) => parse_archive_file(opt, &bytes, archive),
        Object::Unknown(magic) => Err(anyhow::anyhow!("Unknown magic: {:#x}", magic)),
        default => Err(anyhow::anyhow!("Unknown binary type: {default:?}")),
    }
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
