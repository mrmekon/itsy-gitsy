mod generate;
mod git;
mod settings;
mod template;
mod util;

use generate::GitsyGenerator;
use settings::{GitsyCli, GitsySettings};

// TODO:
//
//   * pagination
//   * basic, light, dark, and fancy default themes
//   * better error propagation
//   * automated tests
//   * documentation + examples
//

fn main() {
    let cli = GitsyCli::new();
    let (settings, repo_descriptions) = GitsySettings::new(&cli);
    let generator = GitsyGenerator::new(cli, settings, repo_descriptions);
    generator.generate().expect("Itsy-Gitsy generation failed!");
}
