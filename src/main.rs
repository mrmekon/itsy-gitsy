/*
 * Copyright 2023 Trevor Bentley
 *
 * Author: Trevor Bentley
 * Contact: gitsy@@trevorbentley.com
 * Source: https://github.com/mrmekon/itsy-gitsy
 *
 * This file is part of Itsy-Gitsy.
 *
 * Itsy-Gitsy is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Itsy-Gitsy is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Itsy-Gitsy.  If not, see <http://www.gnu.org/licenses/>.
 */
mod generate;
mod git;
mod settings;
mod template;
mod util;

use generate::GitsyGenerator;
use settings::{GitsyCli, GitsySettings};

fn main() {
    let cli = GitsyCli::new();
    let (settings, repo_descriptions) = GitsySettings::new(&cli);
    let mut generator = GitsyGenerator::new(cli, settings, repo_descriptions);
    match generator.generate() {
        Err(e) => {
            error!("ERROR: {:?}", e);
            panic!("Itsy-Gitsy generation failed!");
        },
        _ => {},
    }
}
