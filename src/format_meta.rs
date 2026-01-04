use anyhow::Error;
use hexplay::{self, CODEPAGE_ASCII, HexViewBuilder};
use metagoblin::{Object, Tag};
use prettytable::{Cell, Row, row};

use crate::Opt;
use crate::format::*;

const SCALE: [char; 100] = [' '; 100];

fn min_max_scale(n: u64, min: u64, max: u64) -> u64 {
    let range = max as f64 - min as f64;
    let offset = n as f64 - min as f64;
    (SCALE.len() as f64 * offset / range).floor() as u64
}

pub struct Meta<'bytes> {
    analysis: metagoblin::Analysis,
    bytes: &'bytes [u8],
    args: Opt,
}

impl<'bytes> Meta<'bytes> {
    pub fn new(object: &Object<'bytes>, bytes: &'bytes [u8], args: Opt) -> Self {
        let analysis = metagoblin::Analysis::new(object);
        Meta {
            analysis,
            bytes,
            args,
        }
    }
    pub fn print_ranges(&self) -> Result<(), Error> {
        let buffer = &self.bytes;
        let mut franges = self.analysis.franges.iter().collect::<Vec<_>>();
        franges.sort_by(|&(r1, _), &(r2, _)| r2.len().cmp(&r1.len()));
        let spaces = (0_usize..100)
            .map(|e| if e % 2 == 0 { "0" } else { "1" })
            .collect::<String>();
        let mut table =
            new_table(row![b->"Name", b->"Tag", b->"Range", b->"Percent", b->"Size", b->spaces]);

        for (range, data) in franges {
            if let Tag::Zero = data.tag {
                continue;
            }
            let size = range.len().saturating_sub(1);
            if size == 0 {
                continue;
            }
            let buffer_length = u64::try_from(buffer.len())?;
            let scaled_min = usize::try_from(min_max_scale(range.min, 0, buffer_length))?;
            let scaled_max = usize::try_from(min_max_scale(range.max, 0, buffer_length))?;
            let scaled_size = min_max_scale(size, 0, buffer_length);
            let mut chars = SCALE;
            if let Some(range) = chars.get_mut(scaled_min..scaled_max) {
                range.fill('-');
            }
            if let Some(c) = chars.get_mut(scaled_min) {
                *c = '|';
            }
            if scaled_max != 0 {
                if let Some(c) = chars.get_mut(scaled_max - 1) {
                    *c = '|';
                }
            }
            let chars = chars.into_iter().collect::<String>();
            let name_cell = string_cell(&self.args, data.name().unwrap_or("None"));
            let range_cell = Cell::new(&format!("{:#x}..{:#x}", range.min, range.max));
            let size_cell = Cell::new(&format!("{}", size));
            table.add_row(Row::new(vec![
                name_cell,
                Cell::new(&format!("{:?}", data.tag)),
                range_cell,
                Cell::new(&format!("{}%", scaled_size)),
                size_cell,
                Cell::new(&chars),
            ]));
        }

        print_table_to_stdout(&table, true).map_err(Into::into)
    }

    pub fn print_hex(&self) -> Result<(), Error> {
        let analysis = &self.analysis;
        let table = HexViewBuilder::new(self.bytes)
            .row_width(16)
            .codepage(CODEPAGE_ASCII);

        let mut colors = Vec::new();
        let franges = analysis.franges.iter().collect::<Vec<_>>();
        for window in franges.windows(2) {
            if let (Some((range, metadata)), Some((_next, _))) = (window.get(0), window.get(1)) {
                let color = match metadata.tag {
                    Tag::Code => hexplay::color::red(),
                    Tag::ASCII => hexplay::color::yellow_bold(),
                    Tag::SymbolTable => hexplay::color::blue_bold(),
                    Tag::Relocation => hexplay::color::green(),
                    Tag::Zero => hexplay::color::white_bold(),
                    Tag::Meta => hexplay::color::magenta(),
                    Tag::Unknown => hexplay::color::black(),
                    _ => hexplay::color::white(),
                };
                let color_range = usize::try_from(range.min)?..usize::try_from(range.max)?;
                colors.push((color, color_range));
            }
        }

        let table = table.add_colors(colors);

        let view = if self.args.color {
            table.force_color().finish()
        } else {
            table.finish()
        };

        view.print()?;
        println!();
        Ok(())
    }
}
