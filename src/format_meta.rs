use goblin::Object;
use {error, Opt};
use metagoblin;
use hexplay::{self, CODEPAGE_ASCII, HexViewBuilder};
use prettytable::cell::Cell;
use prettytable::row::Row;

use format::*;

const SCALE: [char; 100] = [' '; 100];

fn minmaxscale(n: usize, min: usize, max: usize) -> usize {
    (SCALE.len() as f32 * (n as f32 - min as f32) / (max as f32 - min as f32)).floor() as usize
}

pub struct Meta<'a> {
    analysis: metagoblin::Analysis,
    bytes: &'a [u8],
    args: Opt,
}

impl<'a> Meta<'a> {
    pub fn new(object: &Object<'a>, bytes: &'a [u8], args: Opt) -> Self {
        let analysis = metagoblin::Analysis::new(object);
        Meta { analysis, bytes, args }
    }
    pub fn print_ranges(&self) -> Result<(), error::Error> {
        let buffer = &self.bytes;
        let mut franges = self.analysis.franges.iter().collect::<Vec<_>>();
        franges.sort_by(|&(ref r1, _), &(ref r2, _)| r2.len().cmp(&r1.len()));
        let spaces = (0..100)
            .map(|e| if e % 2 == 0 { "0" } else { "1" })
            .collect::<String>();
        let mut table = new_table(
            row![b->"Name", b->"Tag", b->"Range", b->"Percent", b->"Size", b->spaces],
        );

        for &(ref range, ref data) in &franges {
            let size = range.len() - 1;
            if size == 0 {
                continue;
            }
            let scaled_min = minmaxscale(range.min as usize, 0, buffer.len());
            let scaled_max = minmaxscale(range.max as usize, 0, buffer.len());
            let scaled_size = minmaxscale(size as usize, 0, buffer.len());
            let mut chars = SCALE.clone();
            for i in scaled_min..scaled_max {
                chars[i] = '-';
            }
            chars[scaled_min] = '|';
            if scaled_max != 0 {
                chars[scaled_max - 1] = '|';
            }
            let chars = &chars.iter().cloned().collect::<String>();
            let name_cell = string_cell(&self.args, data.name().unwrap_or("None"));
            let range_cell = Cell::new(&format!("{:#x}..{:#x}", range.min, range.max));
            let size_cell = Cell::new(&format!("{}", size));
            table.add_row(Row::new(vec![
                name_cell,
                Cell::new(&format!("{:?}", data.tag)),
                range_cell,
                Cell::new(&format!("{}%", scaled_size)),
                size_cell,
                Cell::new(chars),
            ]));
        }

        table.print_tty(true);
        Ok(())
    }
    pub fn print_hex(&self) -> Result<(), error::Error> {
        let analysis = &self.analysis;
        let table = HexViewBuilder::new(&self.bytes).row_width(16).codepage(
            CODEPAGE_ASCII,
        );

        let mut colors = Vec::new();
        use metagoblin::Tag::*;
        let franges = analysis.franges.iter().collect::<Vec<_>>();
        for window in franges.windows(2) {
            let (range, metadata) = window[0];
            let (_next, _) = window[1];

            // 0xde0..0xde8(8) -> Code - ".init_array" : RW
            // 0xde0..0x1000(544) -> Unknown - "PT_GNU_RELRO"
            // 0xde0..0x1030(592) -> Code - "PT_LOAD" : RW
            // 0xde8..0xdf0(8) -> Code - ".fini_array" : RW

            // 0xdf0..0xfd0(480) -> Meta - ".dynamic"
            // 0xfd0..0x1000(48) -> Code - ".got" : RW
            // 0x1000..0x1020(32) -> Code - ".got.plt" : RW
            // 0x1020..0x1030(16) -> Code - ".data" : RW
            // 0x1030..0x1038(8) -> Zero - ".bss" : RW
            // 0x1030..0x1041(17) -> Code - ".comment" :

            // we can rely on sortedness and this invariant:
            // if range.max <= next.min then this is the most specific tag for this memory range
            // _because_ any previous range, range2, must have this invariant:
            // range2.min <= range.min && range2.max >= range.max
            // e.g., it covers more area, or is exactly equal
            // nevertheless, its still unclear what to do in the case of overlapping ranges

            // if range.min < next.min {}
            // truncate
            //if range.max >= next.min {}

//            print!(
//                "{:#x}..{:#x}({}) -> ",
//                range.min,
//                range.max,
//                range.len() - 1
//            );
//            print!(
//                "{:?} - {:?}",
//                metadata.tag,
//                metadata.name().unwrap_or("None")
//            );
//            if let &Some(ref segment) = &metadata.memory {
//                print!(" : {}", segment.permissions);
//            }
//            println!("");
            let color = match metadata.tag {
                Code => hexplay::color::red(),
                ASCII => hexplay::color::yellow_bold(),
                SymbolTable => hexplay::color::blue_bold(),
                Relocation => hexplay::color::green(),
                Zero => hexplay::color::white_bold(),
                Meta => hexplay::color::magenta(),
                Unknown => hexplay::color::black(),
                _ => hexplay::color::white(),
            };
            colors.push((color, range.min as usize..range.max as usize));
        }

        let table = table.add_colors(colors);

        let view = if self.args.color { table.force_color().finish() } else { table.finish() };

        view.print()?;
        println!();
        Ok(())
    }
}
