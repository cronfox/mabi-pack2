use crate::common;
use anyhow::{Context, Error};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};

pub fn run_list(fname: &str, skey: Option<&str>, output: Option<&str>) -> Result<(), Error> {
    let fp = File::open(fname)?;
    let mut rd = BufReader::new(fp);
    let final_file_name = common::get_final_file_name(fname)?;
    
    let (header, entries, _used_key) = match skey {
        Some(key) => {
            let header = common::read_header(&final_file_name, key, &mut rd)
                .context("读取头部失败")?;
            common::validate_header(&header)?;
            if header.version != 2 {
                return Err(Error::msg(format!(
                    "不支持的头部版本 {}",
                    header.version
                )));
            }
            
            let entries = common::read_entries(&final_file_name, &header, key, &mut rd)
                .context("读取条目失败")?;
            common::validate_entries(&entries)?;
            
            (header, entries, key.to_string())
        },
        None => common::try_read_with_keys(&final_file_name, &mut rd)
            .context("尝试多个密钥失败")?
    };

    let output_stream: Result<Box<dyn Write>, Error> =
        output.map_or(Ok(Box::new(io::stdout())), |path| {
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(path)
                .map(|f| Box::new(f) as Box<dyn Write>)
                .map_err(Error::new)
        });
    let mut output_stream = output_stream?;

    entries.iter().for_each(|e| {
        writeln!(output_stream, "{}", e.name).unwrap();
    });
    Ok(())
}
