use std::collections::BTreeSet;
use std::io::Write;
use std::num::NonZeroUsize;

use anyhow::Error;
use metagoblin::pe;
use metagoblin::pe::characteristic::IMAGE_FILE_BYTES_REVERSED_HI;
use metagoblin::pe::data_directories::DataDirectories;
use metagoblin::pe::export::{Export, Reexport};
use metagoblin::pe::header::*;
use metagoblin::pe::import::Import;
use metagoblin::pe::optional_header::OptionalHeader;
use metagoblin::pe::section_table::{SectionTable, IMAGE_SCN_ALIGN_MASK};
use prettytable::{row, Cell, Row};
use scroll::ctx::StrCtx;
use scroll::Pread;
use termcolor::{Buffer, BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

use crate::format::*;
use crate::Opt;

/// Device drivers and native Windows processes.
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
/// The Windows graphical user interface (GUI) subsystem.
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
/// The Windows character subsystem.
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
/// The OS/2 character subsystem.
const IMAGE_SUBSYSTEM_OS2_CUI: u16 = 5;
/// The POSIX character subsystem.
const IMAGE_SUBSYSTEM_POSIX_CUI: u16 = 7;
/// Native Win9x driver.
const IMAGE_SUBSYSTEM_NATIVE_WINDOWS: u16 = 8;
/// Windows CE.
const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: u16 = 9;
/// An Extensible Firmware Interface (EFI) application.
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
/// An EFI driver with boot services.
const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
/// An EFI driver with run-time services.
const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
/// An EFI ROM image.
const IMAGE_SUBSYSTEM_EFI_ROM: u16 = 13;
/// XBOX.
const IMAGE_SUBSYSTEM_XBOX: u16 = 14;
/// Windows boot application.
const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: u16 = 16;

/// PE32 executable.
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
/// PE32+ executable.
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
/// ROM image.
const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

pub struct PortableExecutable<'bytes> {
    pe: pe::PE<'bytes>,
    bytes: &'bytes [u8],
    args: Opt,
}

fn subsystem_name(subsystem: Option<u16>) -> (&'static str, Color) {
    if let Some(subsystem) = subsystem {
        match subsystem {
            IMAGE_SUBSYSTEM_NATIVE => ("Windows Driver", termcolor::Color::Blue),
            IMAGE_SUBSYSTEM_WINDOWS_GUI => ("Windows GUI Application", termcolor::Color::White),
            IMAGE_SUBSYSTEM_WINDOWS_CUI => {
                ("Windows Console Application", termcolor::Color::Yellow)
            }
            IMAGE_SUBSYSTEM_OS2_CUI => ("OS/2 Console Application", termcolor::Color::Yellow),
            IMAGE_SUBSYSTEM_POSIX_CUI => ("POSIX Console Application", termcolor::Color::Yellow),
            IMAGE_SUBSYSTEM_NATIVE_WINDOWS => ("Windows 9x Driver", termcolor::Color::Blue),
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => {
                ("Windows CE GUI Application", termcolor::Color::White)
            }
            IMAGE_SUBSYSTEM_EFI_APPLICATION => ("EFI Application", termcolor::Color::Magenta),
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => {
                ("EFI Boot Service Driver", termcolor::Color::Magenta)
            }
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => ("EFI Runtime Driver", termcolor::Color::Magenta),
            IMAGE_SUBSYSTEM_EFI_ROM => ("EFI ROM", termcolor::Color::Magenta),
            IMAGE_SUBSYSTEM_XBOX => ("XBOX Application", termcolor::Color::Green),
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => {
                ("Windows Boot Application", termcolor::Color::Blue)
            }
            _ => ("Unknown", termcolor::Color::Red),
        }
    } else {
        ("MS-DOS Application", termcolor::Color::Yellow)
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        COFF_MACHINE_AM33 => "AM33",
        COFF_MACHINE_X86_64 => "X86_64",
        COFF_MACHINE_ARM => "ARM",
        COFF_MACHINE_ARM64 => "AARCH64",
        COFF_MACHINE_ARMNT => "THUMB2",
        COFF_MACHINE_EBC => "EFI_ByteCode",
        COFF_MACHINE_X86 => "X86",
        COFF_MACHINE_IA64 => "IA64",
        COFF_MACHINE_M32R => "M32R",
        COFF_MACHINE_MIPS16 => "MIPS16",
        COFF_MACHINE_MIPSFPU => "MIPS+FPU",
        COFF_MACHINE_MIPSFPU16 => "MIPS16+FPU",
        COFF_MACHINE_POWERPC => "POWERPC",
        COFF_MACHINE_POWERPCFP => "POWERPC+FP",
        COFF_MACHINE_R4000 => "MIPS",
        COFF_MACHINE_RISCV32 => "RISCV32",
        COFF_MACHINE_RISCV64 => "RISCV64",
        COFF_MACHINE_RISCV128 => "RISCV128",
        COFF_MACHINE_SH3 => "SH3",
        COFF_MACHINE_SH3DSP => "SH3_DSP",
        COFF_MACHINE_SH4 => "SH4",
        COFF_MACHINE_SH5 => "SH5",
        COFF_MACHINE_THUMB => "THUMB",
        COFF_MACHINE_WCEMIPSV2 => "MIPSv2_WCE",
        _ => "Unknown",
    }
}

fn pe_kind_name(optional_header: Option<&OptionalHeader>) -> &'static str {
    if let Some(optional_header) = optional_header.as_ref() {
        match optional_header.standard_fields.magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => "PE32",
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => "PE32+",
            IMAGE_ROM_OPTIONAL_HDR_MAGIC => "ROM",
            _ => "Unknown",
        }
    } else {
        "Unknown"
    }
}

fn print_flags(fmt: &mut Buffer, descriptions: &[(&str, &str)], flags: u64) -> Result<(), Error> {
    for (index, &(off, on)) in descriptions.iter().enumerate() {
        let flag = 1_u64 << index;
        if (flags & flag) == 0 {
            if !off.is_empty() {
                writeln!(fmt, "  {}", off)?;
            }
        } else if !on.is_empty() {
            writeln!(fmt, "  {}", on)?;
        }
    }
    Ok(())
}

static CHARACTERISTICS: [(&str, &str); 16] = [
    ("has-relocations", "no-relocations"),
    ("cannot-run", "can-run"),
    ("has-line-numbers", "no-line-numbers"),
    ("has-local-symbols", "no-local-symbols"),
    ("", "trim-working-set"),
    ("only-addresses<2GiB", "supports-addresses>=2GiB"),
    ("", "(unknown)"),
    ("", "little-endian"),
    ("", "32-bits"),
    ("has-debug-info", "no-debug-info"),
    ("", "run-from-swap-if-in-removable-media"),
    ("", "run-from-swap-if-in-network"),
    ("", "is-file-system"),
    ("", "is-dynamic-link-library"),
    ("", "only-uniprocessor"),
    ("", "big-endian"),
];

fn print_characteristics(fmt: &mut Buffer, characteristics: u16) -> Result<(), Error> {
    print_flags(fmt, &CHARACTERISTICS, u64::from(characteristics))
}

static DLL_CHARACTERISTICS: [(&str, &str); 16] = [
    ("", "(unknown)"),
    ("", "(unknown)"),
    ("", "(unknown)"),
    ("", "(unknown)"),
    ("", "(unknown)"),
    (
        "do-not-use-high-entropy-64bit-virtual-address-space",
        "supports-high-entropy-64bit-virtual-address-space",
    ),
    ("not-relocatable", "relocatable"),
    ("do-not-enforce-code-integrity", "enforce-code-integrity"),
    ("do-not-use-no-execute-memory", "supports-no-execute-memory"),
    ("", "do-not-isolate"),
    (
        "has-structured-exception-handlers",
        "no-structured-exception-handling",
    ),
    ("supports-binding", "do-not-bind"),
    ("", "only-in-app-container"),
    ("", "is-wdm-driver"),
    ("no-control-flow-guard", "supports-control-flow-guard"),
    ("no-terminal-server", "supports-terminal-server"),
];

fn print_dll_characteristics(fmt: &mut Buffer, dll_characteristics: u16) -> Result<(), Error> {
    print_flags(fmt, &DLL_CHARACTERISTICS, u64::from(dll_characteristics))
}

static SECTION_CHARACTERISTICS: [&str; 32] = [
    "dsect",
    "no-load",
    "group",
    "not-padded",
    "copy",
    "code",
    "initialized-data",
    "uninitialized-data",
    "other",
    "information",
    "over",
    "remove",
    "comdat",
    "(unknown)",
    "do-not-defer-speculative-exceptions",
    "global-pointer-relative",
    "system-heap",
    "purgeable",
    "locked",
    "preload",
    "",
    "",
    "",
    "",
    "extended-relocations",
    "discardable",
    "not-cachable",
    "not-pageable",
    "shareable",
    "executable",
    "readable",
    "writeable",
];

fn section_characteristic_name(mut section_characteristics: u32) -> String {
    section_characteristics &= !IMAGE_SCN_ALIGN_MASK;

    let mut result = String::with_capacity(128);
    for (index, description) in SECTION_CHARACTERISTICS.iter().enumerate() {
        let flag = 1_u32 << index;
        if (section_characteristics & flag) != 0_u32 {
            if !result.is_empty() {
                result.push(',');
            }
            result.push_str(description);
        }
    }
    result
}

fn section_alignment(section_characteristics: u32) -> Option<NonZeroUsize> {
    let alignment = (section_characteristics & IMAGE_SCN_ALIGN_MASK) >> 20;
    if alignment == 0 || alignment == 0xF {
        None
    } else {
        NonZeroUsize::new(1_usize << (alignment - 1))
    }
}

static DATA_DIRECTORY_KNOWN_NAME: [&str; 15] = [
    "Export table",
    "Import table",
    "Resource table",
    "Exception table",
    "Certificate table",
    "Base relocation table",
    "Debug data",
    "Architecture",
    "Global pointer value",
    "Thread-local storage table",
    "Load configuration table",
    "Bound import table",
    "Import address table",
    "Delay-load import table",
    "Common language runtime header",
];

fn print_data_directory(
    fmt: &mut Buffer,
    data_directories: &DataDirectories,
    sections: &[SectionTable],
    file_alignment: u32,
    writer: &BufferWriter,
    color: bool,
) -> Result<(), Error> {
    let count = data_directories
        .data_directories
        .iter()
        .filter(|e| e.is_some())
        .count();

    fmt_header(fmt, "DataDirectory", count)?;
    let mut table = new_table(row![b->"Idx", b->"Name", b->"RVA", b->"Offset", b->"Size"]);
    for (index, entry) in data_directories.data_directories.iter().enumerate() {
        if let Some(entry) = entry.as_ref() {
            let name = *DATA_DIRECTORY_KNOWN_NAME.get(index).unwrap_or(&"(unknown)");

            let (rva, offset) = if index == 4 {
                // The Certificate Table entry points to a table of attribute certificates.
                // These certificates are not loaded into memory as part of the image.
                // As such, the first field of this entry, which is normally an RVA,
                // is a file pointer instead.
                (
                    Cell::new(""),
                    offsetx_cell(u64::from(entry.virtual_address)),
                )
            } else if let Some(offset) = pe::utils::find_offset(
                usize::try_from(entry.virtual_address)?,
                sections,
                file_alignment,
                &pe::options::ParseOptions::default(),
            ) {
                (
                    addrx_cell(u64::from(entry.virtual_address)),
                    offsetx_cell(u64::try_from(offset)?),
                )
            } else {
                (addrx_cell(u64::from(entry.virtual_address)), Cell::new(""))
            };

            table.add_row(Row::new(vec![
                Cell::new(&format!("{}", index)),
                str_cell(name),
                rva,
                offset,
                sz_cell(u64::from(entry.size)),
            ]));
        }
    }
    flush(fmt, writer, &table, color)?;
    writeln!(fmt)?;
    Ok(())
}

fn print_sections_summary(
    fmt: &mut Buffer,
    section_tables: &[SectionTable],
    writer: &BufferWriter,
    color: bool,
) -> Result<(), Error> {
    if section_tables.is_empty() {
        return Ok(());
    }

    let mut needs_relocations_summary = false;
    let mut needs_line_numbers_summary = false;
    fmt_header(fmt, "SectionsSummary", section_tables.len())?;
    let mut table = new_table(
        row![b->"Name", b->"VirtualAddress", b->"VirtualSize", b->"RawDataPtr", b->"RawDataSize", b->"Align", b->"Characteristics"],
    );
    for entry in section_tables {
        let alignment = if let Some(n) = section_alignment(entry.characteristics) {
            sz_cell(u64::try_from(n.get())?)
        } else {
            Cell::new("")
        };
        let characteristics = section_characteristic_name(entry.characteristics);

        table.add_row(Row::new(vec![
            str_cell(entry.name()?),
            addrx_cell(u64::from(entry.virtual_address)),
            sz_cell(u64::from(entry.virtual_size)),
            offsetx_cell(u64::from(entry.pointer_to_raw_data)),
            sz_cell(u64::from(entry.size_of_raw_data)),
            alignment,
            Cell::new(&characteristics),
        ]));

        needs_relocations_summary |=
            entry.pointer_to_relocations != 0 || entry.number_of_relocations != 0;
        needs_line_numbers_summary |=
            entry.pointer_to_linenumbers != 0 || entry.number_of_linenumbers != 0;
    }

    flush(fmt, writer, &table, color)?;
    writeln!(fmt)?;

    if needs_relocations_summary {
        print_sections_relocations_summary(fmt, section_tables, writer, color)?;
    }

    if needs_line_numbers_summary {
        print_sections_line_numbers_summary(fmt, section_tables, writer, color)?;
    }
    Ok(())
}

fn print_sections_relocations_summary(
    fmt: &mut Buffer,
    section_tables: &[SectionTable],
    writer: &BufferWriter,
    color: bool,
) -> Result<(), Error> {
    if section_tables.is_empty() {
        return Ok(());
    }

    fmt_header(fmt, "SectionsRelocationsSummary", section_tables.len())?;
    let mut table = new_table(row![b->"Name", b->"RelocationPtr", b->"RelocationCount"]);
    for entry in section_tables {
        table.add_row(Row::new(vec![
            Cell::new(entry.name()?),
            addrx_cell(u64::from(entry.pointer_to_relocations)),
            sz_cell(u64::from(entry.number_of_relocations)),
        ]));
    }

    flush(fmt, writer, &table, color)?;
    writeln!(fmt)?;
    Ok(())
}

fn print_sections_line_numbers_summary(
    fmt: &mut Buffer,
    section_tables: &[SectionTable],
    writer: &BufferWriter,
    color: bool,
) -> Result<(), Error> {
    if section_tables.is_empty() {
        return Ok(());
    }

    fmt_header(fmt, "SectionsLineNumbersSummary", section_tables.len())?;
    let mut table = new_table(row![b->"Name", b->"LineNumbersPtr", b->"LineNumbersCount"]);
    for entry in section_tables {
        table.add_row(Row::new(vec![
            Cell::new(entry.name()?),
            addrx_cell(u64::from(entry.pointer_to_linenumbers)),
            sz_cell(u64::from(entry.number_of_linenumbers)),
        ]));
    }

    flush(fmt, writer, &table, color)?;
    writeln!(fmt)?;
    Ok(())
}

fn print_relocations(
    fmt: &mut Buffer,
    section_tables: &[SectionTable],
    bytes: &[u8],
    writer: &BufferWriter,
    color: bool,
) -> Result<(), Error> {
    if section_tables.is_empty() {
        return Ok(());
    }

    for section_table in section_tables {
        if section_table.number_of_relocations == 0 {
            continue;
        }

        let relocations = section_table.relocations(bytes)?;

        fmt_header(
            fmt,
            &format!("Relocations in {}", section_table.name()?),
            usize::from(section_table.number_of_relocations),
        )?;
        let mut table = new_table(row![b->"VirtualAddress", b->"SymbolTableIndex", b->"Type"]);
        for entry in relocations {
            table.add_row(Row::new(vec![
                addrx_cell(u64::from(entry.virtual_address)),
                offsetx_cell(u64::from(entry.symbol_table_index)),
                x_cell(u64::from(entry.typ)),
            ]));
        }
        flush(fmt, writer, &table, color)?;
        writeln!(fmt)?;
    }
    Ok(())
}

fn print_exports(
    fmt: &mut Buffer,
    args: &Opt,
    exports: &[Export],
    writer: &BufferWriter,
    color: bool,
) -> Result<(), Error> {
    if exports.is_empty() {
        return Ok(());
    }

    let mut reexport_libraries = BTreeSet::new();

    fmt_header(fmt, "Exports", exports.len())?;
    let mut table = new_table(row![b->"Offset", b->"RVA", b->"Size", b->"Name"]);
    for entry in exports {
        if let Some(Reexport::DLLName { lib, .. } | Reexport::DLLOrdinal { lib, .. }) =
            entry.reexport
        {
            reexport_libraries.insert(lib);
            continue;
        }

        table.add_row(Row::new(vec![
            offsetx_cell(u64::try_from(entry.offset.unwrap_or(0))?),
            addrx_cell(u64::try_from(entry.rva)?),
            sz_cell(u64::try_from(entry.size)?),
            string_cell(args, entry.name.unwrap_or("")),
        ]));
    }
    flush(fmt, writer, &table, color)?;
    writeln!(fmt)?;

    for reexport_lib in reexport_libraries {
        fmt_header(
            fmt,
            &format!("Reexports from {}", reexport_lib),
            exports.len(),
        )?;
        let mut table =
            new_table(row![b->"Offset", b->"RVA", b->"Size", b->"Name", b->"ReexportIfDifferent"]);
        for entry in exports {
            let reexport_name_or_ordinal = match entry.reexport {
                Some(Reexport::DLLName { export, lib }) => {
                    if lib == reexport_lib {
                        if entry.name == Some(export) {
                            Cell::new("")
                        } else {
                            Cell::new(export)
                        }
                    } else {
                        continue;
                    }
                }

                Some(Reexport::DLLOrdinal { ordinal, lib }) => {
                    if lib == reexport_lib {
                        offsetx_cell(u64::try_from(ordinal)?)
                    } else {
                        continue;
                    }
                }

                None => continue,
            };

            table.add_row(Row::new(vec![
                offsetx_cell(u64::try_from(entry.offset.unwrap_or(0))?),
                addrx_cell(u64::try_from(entry.rva)?),
                sz_cell(u64::try_from(entry.size)?),
                Cell::new(entry.name.unwrap_or("")),
                reexport_name_or_ordinal,
            ]));
        }
        flush(fmt, writer, &table, color)?;
        writeln!(fmt)?;
    }

    Ok(())
}

fn print_imports(
    fmt: &mut Buffer,
    args: &Opt,
    libraries: &[&str],
    imports: &[Import],
    writer: &BufferWriter,
    color: bool,
) -> Result<(), Error> {
    if imports.is_empty() {
        return Ok(());
    }

    for &library in libraries {
        let count = imports.iter().filter(|e| e.dll == library).count();
        fmt_header(fmt, &format!("Imports from {}", library), count)?;
        let mut table = new_table(row![b->"Offset", b->"RVA", b->"Size", b->"Ordinal", b->"Name"]);
        for entry in imports.iter().filter(|e| e.dll == library) {
            table.add_row(Row::new(vec![
                offsetx_cell(u64::try_from(entry.offset)?),
                addrx_cell(u64::try_from(entry.rva)?),
                sz_cell(u64::try_from(entry.size)?),
                offsetx_cell(u64::from(entry.ordinal)),
                string_cell(args, entry.name.as_ref()),
            ]));
        }

        flush(fmt, writer, &table, color)?;
        writeln!(fmt)?;
    }
    Ok(())
}

fn offset_to_rva(offset: u64, base_offset: u64, base_rva: u64) -> u64 {
    base_rva + (offset - base_offset)
}

impl<'bytes> PortableExecutable<'bytes> {
    pub fn new(pe: pe::PE<'bytes>, bytes: &'bytes [u8], args: Opt) -> Self {
        Self { pe, bytes, args }
    }

    fn subsystem(fmt: &mut Buffer, optional_header: Option<&OptionalHeader>) -> Result<(), Error> {
        let subsystem = optional_header.as_ref().map(|h| h.windows_fields.subsystem);
        let (text, color) = subsystem_name(subsystem);
        fmt.set_color(ColorSpec::new().set_intense(true).set_fg(Some(color)))?;
        write!(fmt, "{}", text)?;
        fmt.reset().map_err(Into::into)
    }

    fn print_optional_header(
        fmt: &mut Buffer,
        optional_header: &OptionalHeader,
    ) -> Result<(), Error> {
        write!(fmt, "code: base-address: ")?;
        fmt_addrx(fmt, optional_header.standard_fields.base_of_code)?;
        write!(fmt, " size: ")?;
        fmt_sz(fmt, optional_header.standard_fields.size_of_code)?;
        writeln!(fmt)?;

        write!(fmt, "data: base-address: ")?;
        fmt_addrx(fmt, u64::from(optional_header.standard_fields.base_of_data))?;
        write!(fmt, " initialized-data-size: ")?;
        fmt_sz(
            fmt,
            optional_header.standard_fields.size_of_initialized_data,
        )?;
        write!(fmt, " uninitialized-data-size: ")?;
        fmt_sz(
            fmt,
            optional_header.standard_fields.size_of_uninitialized_data,
        )?;
        writeln!(fmt)?;

        write!(
            fmt,
            "image-version: {}.{}",
            optional_header.windows_fields.major_image_version,
            optional_header.windows_fields.minor_image_version
        )?;
        write!(
            fmt,
            " min-windows-version: {}.{}",
            optional_header
                .windows_fields
                .major_operating_system_version,
            optional_header
                .windows_fields
                .minor_operating_system_version
        )?;
        write!(
            fmt,
            " min-subsystem-version: {}.{}",
            optional_header.windows_fields.major_subsystem_version,
            optional_header.windows_fields.minor_subsystem_version
        )?;
        write!(
            fmt,
            " linker-version: {}.{}",
            optional_header.standard_fields.major_linker_version,
            optional_header.standard_fields.minor_linker_version
        )?;
        writeln!(fmt)?;

        write!(fmt, "image: preferred-base-address: ")?;
        fmt_addrx(fmt, optional_header.windows_fields.image_base)?;
        write!(fmt, " size: ")?;
        fmt_sz(fmt, u64::from(optional_header.windows_fields.size_of_image))?;
        write!(fmt, " check-sum: ")?;
        fmt_addrx(fmt, u64::from(optional_header.windows_fields.check_sum))?;
        writeln!(fmt)?;

        write!(fmt, "stack: reserve-size: ")?;
        fmt_sz(fmt, optional_header.windows_fields.size_of_stack_reserve)?;
        write!(fmt, " commit-size: ")?;
        fmt_sz(fmt, optional_header.windows_fields.size_of_stack_commit)?;
        writeln!(fmt)?;

        write!(fmt, "heap: reserve-size: ")?;
        fmt_sz(fmt, optional_header.windows_fields.size_of_heap_reserve)?;
        write!(fmt, " commit-size: ")?;
        fmt_sz(fmt, optional_header.windows_fields.size_of_heap_commit)?;
        writeln!(fmt).map_err(Into::into)
    }

    pub fn print(&self) -> Result<(), Error> {
        let cc = if self.args.color || atty::is(atty::Stream::Stdout) {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let coff_header = &self.pe.header.coff_header;
        let endianness = if (coff_header.characteristics & IMAGE_FILE_BYTES_REVERSED_HI) == 0 {
            "little-endian"
        } else {
            "big-endian"
        };

        let optional_header = self.pe.header.optional_header.as_ref();
        let windows_fields = optional_header.map(|h| &h.windows_fields);

        fmt_hdr(fmt, pe_kind_name(optional_header))?;
        write!(fmt, " ")?;
        Self::subsystem(fmt, optional_header)?;
        write!(fmt, " ")?;
        fmt_name_bold(fmt, machine_name(coff_header.machine))?;
        write!(fmt, "-{} @ ", endianness)?;
        fmt_addrx(fmt, u64::try_from(self.pe.entry)?)?;
        writeln!(fmt, ":")?;
        writeln!(fmt)?;

        write!(fmt, "pe-pointer: ")?;
        fmt_off(fmt, u64::from(self.pe.header.dos_header.pe_pointer))?;
        write!(fmt, " optional-header-size: ")?;
        fmt_sz(fmt, u64::from(coff_header.size_of_optional_header))?;
        if let Some(windows_fields) = windows_fields {
            write!(fmt, " headers-size: ")?;
            fmt_sz(fmt, u64::from(windows_fields.size_of_headers))?;

            write!(fmt, " file-alignment: ")?;
            fmt_sz(fmt, u64::from(windows_fields.file_alignment))?;
        }
        writeln!(fmt, " time-date-stamp: {:#x}", coff_header.time_date_stamp)?;

        write!(fmt, "sections: count: ")?;
        fmt_sz(fmt, u64::from(coff_header.number_of_sections))?;
        if let Some(windows_fields) = windows_fields {
            write!(fmt, " alignment: ")?;
            fmt_sz(fmt, u64::from(windows_fields.section_alignment))?;
        }
        writeln!(fmt)?;

        write!(fmt, "symbol-table: pointer: ")?;
        fmt_off(fmt, u64::from(coff_header.pointer_to_symbol_table))?;
        write!(fmt, " entries-count: ")?;
        fmt_sz(fmt, u64::from(coff_header.number_of_symbol_table))?;
        writeln!(fmt)?;

        if let Some(optional_header) = optional_header {
            Self::print_optional_header(fmt, optional_header)?;
        } else {
            writeln!(fmt, "optional-header: (absent)")?;
        }

        if let Some(debug_guid) = self
            .pe
            .debug_data
            .as_ref()
            .and_then(pe::debug::DebugData::guid)
        {
            write!(fmt, "debug-guid: ")?;
            for i in debug_guid {
                write!(fmt, "{:02x}", i)?;
            }
            writeln!(fmt)?;
        }

        writeln!(fmt)?;
        writeln!(fmt, "Characteristics:")?;
        print_characteristics(fmt, coff_header.characteristics)?;
        if let Some(windows_fields) = windows_fields {
            print_dll_characteristics(fmt, windows_fields.dll_characteristics)?;
        }
        writeln!(fmt)?;

        print_sections_summary(fmt, &self.pe.sections, &writer, self.args.color)?;

        if let Some(optional_header) = optional_header {
            print_data_directory(
                fmt,
                &optional_header.data_directories,
                &self.pe.sections,
                optional_header.windows_fields.file_alignment,
                &writer,
                self.args.color,
            )?;
        }

        print_exports(fmt, &self.args, &self.pe.exports, &writer, self.args.color)?;

        print_imports(
            fmt,
            &self.args,
            &self.pe.libraries,
            &self.pe.imports,
            &writer,
            self.args.color,
        )?;

        print_relocations(fmt, &self.pe.sections, self.bytes, &writer, self.args.color)?;

        writer.print(fmt).map_err(Into::into)
    }

    pub fn search(&self, search: &str) -> Result<(), Error> {
        let cc = if self.args.color || atty::is(atty::Stream::Stdout) {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let mut matches = Vec::new();
        for i in 0..self.bytes.len() {
            if let Ok(res) = self
                .bytes
                .pread_with::<&str>(i, StrCtx::Length(search.len()))
            {
                if res == search {
                    matches.push(i);
                }
            }
        }

        writeln!(fmt)?;
        writeln!(fmt, "Matches for {:?}:", search)?;

        for offset in matches.into_iter().map(u64::try_from) {
            let offset = offset?;

            writeln!(fmt, "  {:#x}", offset)?;

            if let Some(optional_header) = self.pe.header.optional_header.as_ref() {
                for (index, data_directory) in optional_header
                    .data_directories
                    .data_directories
                    .iter()
                    .enumerate()
                {
                    if let Some(data_directory) = data_directory.as_ref() {
                        if let Some(data_directory_offset) = pe::utils::find_offset(
                            usize::try_from(data_directory.virtual_address)?,
                            &self.pe.sections,
                            optional_header.windows_fields.file_alignment,
                            &pe::options::ParseOptions::default(),
                        ) {
                            let data_directory_offset = u64::try_from(data_directory_offset)?;
                            let offset_end = data_directory_offset + u64::from(data_directory.size);

                            if offset >= data_directory_offset && offset < offset_end {
                                let name =
                                    *DATA_DIRECTORY_KNOWN_NAME.get(index).unwrap_or(&"(unknown)");

                                write!(fmt, "  ├──{}({}) ∈ ", name, index)?;
                                let rva = offset_to_rva(
                                    offset,
                                    data_directory_offset,
                                    u64::from(data_directory.virtual_address),
                                );
                                fmt_addrx(fmt, rva)?;
                                writeln!(fmt)?;
                            }
                        }
                    }
                }
            }

            for (index, section) in self.pe.sections.iter().enumerate() {
                let pointer_to_raw_data = u64::from(section.pointer_to_raw_data);
                let offset_end = pointer_to_raw_data + u64::from(section.size_of_raw_data);

                if offset >= pointer_to_raw_data && offset < offset_end {
                    if let Ok(name) = section.name() {
                        write!(fmt, "  ├──Section {}({}) ∈ ", name, index)?;
                    } else {
                        write!(fmt, "  ├──Section ({}) ∈ ", index)?;
                    }

                    let rva = offset_to_rva(
                        offset,
                        pointer_to_raw_data,
                        u64::from(section.virtual_address),
                    );
                    fmt_addrx(fmt, rva)?;
                    writeln!(fmt)?;
                }
            }
        }
        writer.print(fmt)?;
        Ok(())
    }
}

pub(crate) fn is_pe_object_file_header(bytes: &[u8]) -> bool {
    let mut offset = 0;
    if let Ok(header) = CoffHeader::parse(bytes, &mut offset) {
        offset == SIZEOF_COFF_HEADER
            && header.size_of_optional_header == 0
            && matches!(
                header.machine,
                COFF_MACHINE_UNKNOWN
                    | COFF_MACHINE_AM33
                    | COFF_MACHINE_X86_64
                    | COFF_MACHINE_ARM
                    | COFF_MACHINE_ARM64
                    | COFF_MACHINE_ARMNT
                    | COFF_MACHINE_EBC
                    | COFF_MACHINE_X86
                    | COFF_MACHINE_IA64
                    | COFF_MACHINE_M32R
                    | COFF_MACHINE_MIPS16
                    | COFF_MACHINE_MIPSFPU
                    | COFF_MACHINE_MIPSFPU16
                    | COFF_MACHINE_POWERPC
                    | COFF_MACHINE_POWERPCFP
                    | COFF_MACHINE_R4000
                    | COFF_MACHINE_RISCV32
                    | COFF_MACHINE_RISCV64
                    | COFF_MACHINE_RISCV128
                    | COFF_MACHINE_SH3
                    | COFF_MACHINE_SH3DSP
                    | COFF_MACHINE_SH4
                    | COFF_MACHINE_SH5
                    | COFF_MACHINE_THUMB
                    | COFF_MACHINE_WCEMIPSV2
            )
    } else {
        false
    }
}

pub struct PEObjectFile<'bytes> {
    coff: pe::Coff<'bytes>,
    bytes: &'bytes [u8],
    args: Opt,
}

impl<'bytes> PEObjectFile<'bytes> {
    pub fn new(coff: pe::Coff<'bytes>, bytes: &'bytes [u8], args: Opt) -> Self {
        Self { coff, bytes, args }
    }

    pub fn print(&self) -> Result<(), Error> {
        let args = &self.args;
        let color = args.color;

        let cc = if args.color || atty::is(atty::Stream::Stdout) {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let endianness = if (self.coff.header.characteristics & IMAGE_FILE_BYTES_REVERSED_HI) == 0 {
            "little-endian"
        } else {
            "big-endian"
        };

        write!(fmt, "ObjectFile(PE/COFF) ")?;
        fmt_name_bold(fmt, machine_name(self.coff.header.machine))?;
        writeln!(fmt, "-{}", endianness)?;

        writeln!(
            fmt,
            "time-date-stamp: {:#x}",
            self.coff.header.time_date_stamp
        )?;

        write!(fmt, "symbol-table: pointer: ")?;
        fmt_off(fmt, u64::from(self.coff.header.pointer_to_symbol_table))?;
        write!(fmt, " entries-count: ")?;
        fmt_sz(fmt, u64::from(self.coff.header.number_of_symbol_table))?;
        writeln!(fmt)?;

        writeln!(fmt)?;
        writeln!(fmt, "Characteristics:")?;
        print_characteristics(fmt, self.coff.header.characteristics)?;
        writeln!(fmt)?;

        print_sections_summary(fmt, &self.coff.sections, &writer, color)?;

        print_relocations(fmt, &self.coff.sections, self.bytes, &writer, color)?;

        writer.print(fmt)?;
        Ok(())
    }

    pub fn search(&self, search: &str) -> Result<(), Error> {
        let cc = if self.args.color || atty::is(atty::Stream::Stdout) {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        };
        let writer = BufferWriter::stdout(cc);
        let fmt = &mut writer.buffer();

        let mut matches = Vec::new();
        for i in 0..self.bytes.len() {
            if let Ok(res) = self
                .bytes
                .pread_with::<&str>(i, StrCtx::Length(search.len()))
            {
                if res == search {
                    matches.push(i);
                }
            }
        }

        writeln!(fmt)?;
        writeln!(fmt, "Matches for {:?}:", search)?;

        for offset in matches.into_iter().map(u64::try_from) {
            let offset = offset?;

            writeln!(fmt, "  {:#x}", offset)?;

            for (index, section) in self.coff.sections.iter().enumerate() {
                let pointer_to_raw_data = u64::from(section.pointer_to_raw_data);
                let offset_end = pointer_to_raw_data + u64::from(section.size_of_raw_data);

                if offset >= pointer_to_raw_data && offset < offset_end {
                    if let Ok(name) = section.name() {
                        write!(fmt, "  ├──Section {}({}) ∈ ", name, index)?;
                    } else {
                        write!(fmt, "  ├──Section ({}) ∈ ", index)?;
                    }

                    let rva = offset_to_rva(
                        offset,
                        pointer_to_raw_data,
                        u64::from(section.virtual_address),
                    );
                    fmt_addrx(fmt, rva)?;
                    writeln!(fmt)?;
                }
            }
        }
        writer.print(fmt)?;
        Ok(())
    }
}
