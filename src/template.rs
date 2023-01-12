use crate::git::GitFile;
use chrono::{naive::NaiveDateTime, offset::FixedOffset, DateTime};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use tera::{to_value, try_get_value, Filter, Function, Value};

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
    pub fn new(cur: usize, total: usize, url_template: &str) -> Self {
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
