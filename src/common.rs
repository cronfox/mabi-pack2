use crate::encryption;
use anyhow::Error;
use byte_slice_cast::AsSliceOf;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub struct FileHeader {
    pub checksum: u32,
    pub version: u8,
    pub file_cnt: u32,
}

impl FileHeader {
    pub fn new<T>(reader: &mut T) -> Result<Self, std::io::Error>
    where
        T: Read,
    {
        Ok(FileHeader {
            checksum: reader.read_u32::<LittleEndian>()?,
            version: reader.read_u8()?,
            file_cnt: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
pub struct FileEntry {
    pub name: String,
    pub checksum: u32,
    pub flags: u32, // 1: compressed; 2: is_encrypted; 4: head_encrypted; 8: ?
    pub offset: u32,
    pub original_size: u32, // decompressed size
    pub raw_size: u32,      // compressed size
    pub key: [u8; 16],
}

pub const FLAG_COMPRESSED: u32 = 1;
pub const FLAG_ALL_ENCRYPTED: u32 = 2;
pub const FLAG_HEAD_ENCRYPTED: u32 = 4;

impl FileEntry {
    pub fn new<T>(reader: &mut T) -> Result<Self, std::io::Error>
    where
        T: Read,
    {
        let str_len = reader.read_u32::<LittleEndian>()?;
        let mut fname = vec![0u8; str_len as usize * 2];
        reader.read_exact(&mut fname)?;
        let fname = String::from_utf16(fname.as_slice_of::<u16>().unwrap())
            .expect("file entry string format error");

        let mut ent = FileEntry {
            name: fname,
            checksum: reader.read_u32::<LittleEndian>()?,
            flags: reader.read_u32::<LittleEndian>()?,
            offset: reader.read_u32::<LittleEndian>()?,
            original_size: reader.read_u32::<LittleEndian>()?,
            raw_size: reader.read_u32::<LittleEndian>()?,
            key: [0; 16],
        };
        reader.read_exact(&mut ent.key)?;
        Ok(ent)
    }
}

pub fn get_final_file_name(fname: &str) -> Result<String, Error> {
    Path::new(fname)
        .file_name()
        .ok_or(Error::msg("not a valid file path"))
        .map(|s| s.to_str().expect("not a valid unicode string").to_owned())
}

pub fn read_header<T>(fname: &str,skey:&str, rd: &mut T) -> Result<FileHeader, Error>
where
    T: Read + Seek,
{
    let key = encryption::gen_header_key(fname,skey);
    let offset = encryption::gen_header_offset(&fname);
    rd.seek(SeekFrom::Start(offset as u64))?;
    let mut dec_stream = encryption::Snow2Decoder::new(&key, rd);
    Ok(FileHeader::new(&mut dec_stream)?)
}

pub fn validate_header(hdr: &FileHeader) -> Result<(), Error> {
    if hdr.version as u32 + hdr.file_cnt != hdr.checksum {
        Err(Error::msg("header checksum wrong"))
    } else {
        Ok(())
    }
}

pub fn read_entries<T>(
    fname: &str,
    header: &FileHeader,
    skey:&str,
    rd: &mut T,
) -> Result<Vec<FileEntry>, Error>
where
    T: Read + Seek,
{
    let key = encryption::gen_entries_key(&fname,skey);
    let offset_header = encryption::gen_header_offset(&fname);
    let offset_entry = encryption::gen_entries_offset(&fname);
    //println!("header offset: {:x}", offset_header);
    //println!("entry offset: {:x}", offset_entry);
    rd.seek(SeekFrom::Start((offset_header + offset_entry) as u64))?;

    let mut dec_stream = encryption::Snow2Decoder::new(&key, rd);
    (0..header.file_cnt)
        .map(|_| FileEntry::new(&mut dec_stream).map_err(Error::new))
        .collect()
}

pub fn validate_entries(entries: &[FileEntry]) -> Result<(), Error> {
    for ent in entries {
        let key_sum = ent.key.iter().fold(0u32, |s, v| s + *v as u32);
        if ent.flags + ent.offset + ent.original_size + ent.raw_size + key_sum != ent.checksum {
            return Err(Error::msg(format!(
                "entry checksum wrong, file name: {}",
                ent.name
            )));
        }
    }
    Ok(())
}

pub const KEY_SALT_LIST: [&str; 10] = [
    "3@6|3a[@<Ex:L=eN|g",
    "CuAVPMZx:E96:(Rxdw",
    "@6QeTuOaDgJlZcBm#9",
    "DaXU_Vx9xy;[ycFz{1",
    "}F33F0}_7X^;b?PM/;",
    "C(K^x&pBEeg7A5;{G9",
    "smh=Pdw+%?wk?m4&(y",
    "xGqK]W+_eM5u3[8-8u",
    "1&w2!&w{Q)Fkz4e&p0",
    "})wWb4?-sVGHNoPKpc"
];

pub fn try_read_with_keys<T>(
    fname: &str, 
    rd: &mut T
) -> Result<(FileHeader, Vec<FileEntry>, String), Error>
where
    T: Read + Seek,
{
    for &key_salt in KEY_SALT_LIST.iter() {
        // 保存当前位置
        let start_pos = rd.seek(SeekFrom::Start(0))?;
        
        // 使用闭包进行一次完整的验证流程，任何步骤失败都会继续下一个密钥
        match (|| -> Result<(FileHeader, Vec<FileEntry>), Error> {
            // 尝试读取头部
            let header = read_header(fname, key_salt, rd)?;
            validate_header(&header)?;
            
            if header.version != 2 {
                return Err(Error::msg(format!("不支持的头部版本 {}", header.version)));
            }
            
            // 尝试读取条目
            let entries = read_entries(fname, &header, key_salt, rd)?;
            validate_entries(&entries)?;
            
            // 只有当头部和条目都成功验证时才返回成功
            Ok((header, entries))
        })() {
            Ok((header, entries)) => {
                println!("找到匹配的密钥: {}", key_salt);
                return Ok((header, entries, key_salt.to_string()));
            },
            Err(_) => {
                // 密钥验证失败，重置位置准备尝试下一个密钥
                rd.seek(SeekFrom::Start(start_pos))?;
            }
        }
    }
    
    Err(Error::msg("无法找到有效的密钥盐值，请手动指定"))
}
