const SCALE: [char; 100] = [' '; 100];

fn minmaxscale(n: usize, min: usize, max: usize) -> usize {
     (SCALE.len() as f32 * (n as f32 - min as f32) / (max as f32 - min as f32)).floor() as usize
}
