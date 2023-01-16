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
use crate::git::GitFile;
use crate::util::{sanitize_path_component, urlify_path};
use chrono::{naive::NaiveDateTime, offset::FixedOffset, DateTime};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tera::{from_value, to_value, try_get_value, Filter, Function, Value};

fn ts_to_date(ts: i64, offset: Option<i64>, format: Option<String>) -> String {
    let offset = offset.unwrap_or(0);
    let dt = NaiveDateTime::from_timestamp_opt(ts + offset, 0).expect("Invalid timestamp");
    let dt_tz: DateTime<FixedOffset> =
        DateTime::from_local(dt, FixedOffset::east_opt(offset as i32).expect("Invalid timezone"));
    match format {
        Some(f) => dt_tz.format(&f).to_string(),
        None => dt_tz.format("%Y-%m-%d").to_string(),
    }
}

fn ts_to_git_timestamp(ts: i64, offset: Option<i64>) -> String {
    let offset = offset.unwrap_or(0);
    let dt = chrono::naive::NaiveDateTime::from_timestamp_opt(ts + offset, 0).expect("invalid timestamp");
    let dt_tz: DateTime<FixedOffset> =
        DateTime::from_local(dt, FixedOffset::east_opt(offset as i32).expect("Invalid timezone"));
    dt_tz.format("%a %b %e %T %Y %z").to_string()
}

pub struct FileFilter;
impl Filter for FileFilter {
    fn filter(&self, value: &Value, _args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let file_list: Vec<GitFile> = try_get_value!("only_files", "value", Vec<GitFile>, value);
        let file_list: Vec<GitFile> = file_list
            .iter()
            .filter_map(|x| match x.kind.as_str() {
                "file" => Some(x.clone()),
                _ => None,
            })
            .collect();
        Ok(to_value(file_list).unwrap())
    }
}

pub struct DirFilter;
impl Filter for DirFilter {
    fn filter(&self, value: &Value, _args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let file_list: Vec<GitFile> = try_get_value!("only_dirs", "value", Vec<GitFile>, value);
        let file_list: Vec<GitFile> = file_list
            .iter()
            .filter_map(|x| match x.kind.as_str() {
                "dir" => Some(x.clone()),
                _ => None,
            })
            .collect();
        Ok(to_value(file_list).unwrap())
    }
}

pub struct HexFilter;
impl Filter for HexFilter {
    fn filter(&self, value: &Value, _args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let v: i64 = try_get_value!("hex", "value", i64, value);
        Ok(to_value(format!("{:x}", v)).unwrap())
    }
}

pub struct OctFilter;
impl Filter for OctFilter {
    fn filter(&self, value: &Value, _args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let v: i64 = try_get_value!("oct", "value", i64, value);
        Ok(to_value(format!("{:o}", v)).unwrap())
    }
}

pub struct MaskFilter;
impl Filter for MaskFilter {
    fn filter(&self, value: &Value, args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let v: u64 = try_get_value!("mask", "value", u64, value);
        let mask: String = from_value(
            args.get("mask")
                .expect("ERROR: Tera mask filter called without `mask` parameter.")
                .clone(),
        )
            .expect("ERROR: Tera `mask` parameter is not valid.");
        let mask: u64 = match mask.starts_with("0x") {
            true => {
                let hexstr = mask.strip_prefix("0x").unwrap();
                u64::from_str_radix(hexstr, 16)
                    .expect("ERROR: Tera `mask` parameter is invalid hex.")
            },
            false => {
                str::parse::<u64>(&mask).expect("ERROR: Tera `mask` parameter is not valid.")
            },
        };
        Ok(to_value(v & mask).unwrap())
    }
}

pub struct UrlStringFilter;
impl Filter for UrlStringFilter {
    fn filter(&self, value: &Value, _args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let v: String = try_get_value!("url_string", "value", String, value);
        let sanitized = sanitize_path_component(&urlify_path(&v));
        Ok(to_value(sanitize_path_component(&sanitized)).unwrap())
    }
}

pub struct TsDateFn;
impl Function for TsDateFn {
    fn call(&self, args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let ts: Option<i64> = match args.get("ts") {
            Some(ts) => match tera::from_value(ts.clone()) {
                Ok(ts) => Some(ts),
                _ => None,
            },
            _ => None,
        };
        let ts = ts.expect("ts_to_date missing a `ts` argument");

        let tz: Option<i64> = match args.get("tz") {
            Some(tz) => match tera::from_value(tz.clone()) {
                Ok(tz) => Some(tz),
                _ => None,
            },
            _ => None,
        };

        let fmt: Option<String> = match args.get("fmt") {
            Some(fmt) => match tera::from_value(fmt.clone()) {
                Ok(fmt) => Some(fmt),
                _ => None,
            },
            _ => None,
        };
        Ok(to_value(ts_to_date(ts, tz, fmt)).unwrap())
    }
}

pub struct TsTimestampFn;
impl Function for TsTimestampFn {
    fn call(&self, args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let ts: Option<i64> = match args.get("ts") {
            Some(ts) => match tera::from_value(ts.clone()) {
                Ok(ts) => Some(ts),
                _ => None,
            },
            _ => None,
        };
        let ts = ts.expect("ts_to_git_timestamp missing a `ts` argument");

        let tz: Option<i64> = match args.get("tz") {
            Some(tz) => match tera::from_value(tz.clone()) {
                Ok(tz) => Some(tz),
                _ => None,
            },
            _ => None,
        };
        Ok(to_value(ts_to_git_timestamp(ts, tz)).unwrap())
    }
}

#[derive(Serialize)]
pub struct Pagination {
    pub pages: usize,
    pub page_idx: usize,
    pub page_str: String,
    pub cur_page: String,
    pub next_page: Option<String>,
    pub prev_page: Option<String>,
}
impl Pagination {
    pub fn new<P: AsRef<Path>>(cur: usize, total: usize, url_template: &P) -> Self {
        let url_template = url_template.as_ref().to_str()
            .expect(&format!("ERROR: attempted to paginate unparseable path: {}",
                             url_template.as_ref().display()));
        let digits = total.to_string().len().max(2);
        let next = match cur + 1 <= total {
            true => Some(cur + 1),
            false => None,
        };
        let prev = match cur <= 1 {
            true => None,
            false => Some(cur - 1),
        };
        let cur_str = match cur <= 1 {
            true => String::new(),
            false => format!("{:0w$}", cur, w = digits),
        };
        let next_str = match next.unwrap_or(0) <= 1 {
            true => String::new(),
            false => format!("{:0w$}", next.unwrap_or(0), w = digits),
        };
        let prev_str = match prev.unwrap_or(0) <= 1 {
            true => String::new(),
            false => format!("{:0w$}", prev.unwrap_or(0), w = digits),
        };
        let cur_page = url_template.replace("%PAGE%", &cur_str);
        let next_page = match next {
            Some(_) => Some(url_template.replace("%PAGE%", &next_str)),
            _ => None,
        };
        let prev_page = match prev {
            Some(_) => Some(url_template.replace("%PAGE%", &prev_str)),
            _ => None,
        };
        Pagination {
            pages: total,
            page_idx: cur,
            page_str: cur_str.clone(),
            cur_page,
            next_page,
            prev_page,
        }
    }

    pub fn with_relative_paths(&self) -> Self {
        let cur_page = {
            let path = PathBuf::from(&self.cur_page);
            path.file_name()
                .expect(&format!("Invalid output filename: {}", self.cur_page))
                .to_string_lossy()
                .to_string()
        };
        let next_page = match &self.next_page {
            Some(p) => {
                let path = PathBuf::from(p);
                Some(
                    path.file_name()
                        .expect(&format!("Invalid output filename: {}", p))
                        .to_string_lossy()
                        .to_string(),
                )
            }
            _ => None,
        };
        let prev_page = match &self.prev_page {
            Some(p) => {
                let path = PathBuf::from(p);
                Some(
                    path.file_name()
                        .expect(&format!("Invalid output filename: {}", p))
                        .to_string_lossy()
                        .to_string(),
                )
            }
            _ => None,
        };
        Pagination {
            pages: self.pages,
            page_idx: self.page_idx,
            page_str: self.page_str.clone(),
            cur_page,
            next_page,
            prev_page,
        }
    }
}
