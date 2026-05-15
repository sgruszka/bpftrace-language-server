use binrw::BinRead;
use enum_dispatch::enum_dispatch;
use memmap2::{Mmap, MmapOptions};
use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

use std::ffi::CStr;
use std::os::raw::c_char;
// use crate::log_mod::{self, BTFRD};
// use crate::{log_dbg, log_err};

#[derive(Debug, BinRead)]
// #[br(magic = 0xeb9fu16)]
struct BtfHeader {
    magic: u16,
    _version: u8,
    _flags: u8,
    hdr_len: u32,

    type_off: u32,
    type_len: u32,
    str_off: u32,
    _str_len: u32,
}

impl BtfHeader {
    fn read<R: Read + Seek>(reader: &mut R) -> binrw::BinResult<Self> {
        let hdr = BtfHeader::read_ne(reader)?;
        if hdr.magic != 0xeb9fu16 {
            if hdr.magic == 0x9feb {
                return Err(binrw::Error::AssertFail {
                    pos: 0,
                    message: "BTF data not in native endian".to_owned(),
                });
            } else {
                return Err(binrw::Error::BadMagic {
                    pos: 0,
                    found: Box::new(hdr.magic),
                });
            }
        }
        Ok(hdr)
    }
}

const BTF_KIND_INT: u32 = 1;
const BTF_KIND_PTR: u32 = 2;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FWD: u32 = 7;
const BTF_KIND_TYPEDEF: u32 = 8;
const BTF_KIND_VOLATILE: u32 = 9;
const BTF_KIND_CONST: u32 = 10;
const BTF_KIND_RESTRICT: u32 = 11;
const BTF_KIND_FUNC: u32 = 12;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_FLOAT: u32 = 16;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_TYPE_TAG: u32 = 18;
const BTF_KIND_ENUM64: u32 = 19;

#[derive(Debug, BinRead)]
struct BtfRawType {
    name_off: u32,
    info: u32,
    union_size_type: u32,
}

macro_rules! u32_get_field {
    ($value:expr, $from:literal, $to:literal) => {{
        const _: () = assert!($to >= 0 && $to <= 31);
        const _: () = assert!($from >= 0 && $from <= 31);
        const _: () = assert!($to >= $from);
        let width = $to - $from + 1;
        if width == 32 {
            $value
        } else {
            ($value >> $from) & ((1u32 << width) - 1)
        }
    }};
}

impl BtfRawType {
    fn get_kind(&self) -> u32 {
        u32_get_field!(self.info, 24, 28)
    }

    fn get_vlen(&self) -> u32 {
        u32_get_field!(self.info, 0, 15)
    }

    fn get_type(&self) -> u32 {
        self.union_size_type
    }
}

#[derive(Debug)]
struct BtfTypeInteger {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypePointer {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeArray {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeUnion {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeStruct {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeEnum {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeFwd {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeTypedef {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeVolatile {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeConst {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeRestrict {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeFunc {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeFuncProto {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeVar {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeDatasec {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeFloat {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeDeclTag {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeTypeTag {
    btf_raw_type: BtfRawType,
}

#[derive(Debug)]
struct BtfTypeEnum64 {
    btf_raw_type: BtfRawType,
}

#[enum_dispatch]
trait BtfTypeTrait {
    fn kind_specific_size(&self) -> u64;
}

impl BtfTypeTrait for BtfTypeInteger {
    fn kind_specific_size(&self) -> u64 {
        4
    }
}

impl BtfTypeTrait for BtfTypePointer {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeArray {
    fn kind_specific_size(&self) -> u64 {
        12
    }
}

impl BtfTypeTrait for BtfTypeUnion {
    fn kind_specific_size(&self) -> u64 {
        let vlen = u32_get_field!(self.btf_raw_type.info, 0, 15) as u64;
        vlen * 12
    }
}

impl BtfTypeTrait for BtfTypeStruct {
    fn kind_specific_size(&self) -> u64 {
        let vlen = u32_get_field!(self.btf_raw_type.info, 0, 15) as u64;
        vlen * 12
    }
}

impl BtfTypeTrait for BtfTypeEnum {
    fn kind_specific_size(&self) -> u64 {
        let vlen = u32_get_field!(self.btf_raw_type.info, 0, 15) as u64;
        vlen * 8
    }
}

impl BtfTypeTrait for BtfTypeFwd {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeTypedef {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeVolatile {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeConst {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeRestrict {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeFunc {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeFuncProto {
    fn kind_specific_size(&self) -> u64 {
        let vlen = self.btf_raw_type.get_vlen() as u64;
        vlen * 8
    }
}

impl BtfTypeTrait for BtfTypeVar {
    fn kind_specific_size(&self) -> u64 {
        4
    }
}

impl BtfTypeTrait for BtfTypeDatasec {
    fn kind_specific_size(&self) -> u64 {
        let vlen = self.btf_raw_type.get_vlen() as u64;
        vlen * 12
    }
}

impl BtfTypeTrait for BtfTypeFloat {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}
impl BtfTypeTrait for BtfTypeDeclTag {
    fn kind_specific_size(&self) -> u64 {
        4
    }
}

impl BtfTypeTrait for BtfTypeTypeTag {
    fn kind_specific_size(&self) -> u64 {
        0
    }
}

impl BtfTypeTrait for BtfTypeEnum64 {
    fn kind_specific_size(&self) -> u64 {
        let vlen = self.btf_raw_type.get_vlen() as u64;
        vlen * 12
    }
}

#[enum_dispatch(BtfTypeTrait)]
enum BtfType {
    Int(BtfTypeInteger),
    Ptr(BtfTypePointer),
    Array(BtfTypeArray),
    Union(BtfTypeUnion),
    Struct(BtfTypeStruct),
    Enum(BtfTypeEnum),
    Fwd(BtfTypeFwd),
    Typedef(BtfTypeTypedef),
    Volatile(BtfTypeVolatile),
    Const(BtfTypeConst),
    Restrict(BtfTypeRestrict),
    Func(BtfTypeFunc),
    FuncProto(BtfTypeFuncProto),
    Var(BtfTypeVar),
    Datasec(BtfTypeDatasec),
    Float(BtfTypeFloat),
    DeclTag(BtfTypeDeclTag),
    TypeTag(BtfTypeTypeTag),
    Enum64(BtfTypeEnum64),
}

fn to_btf_type(btf_raw_type: BtfRawType) -> Result<BtfType, binrw::Error> {
    let kind = btf_raw_type.get_kind();
    match kind {
        BTF_KIND_INT => Ok(BtfType::Int(BtfTypeInteger { btf_raw_type })),
        BTF_KIND_PTR => Ok(BtfType::Ptr(BtfTypePointer { btf_raw_type })),
        BTF_KIND_ARRAY => Ok(BtfType::Array(BtfTypeArray { btf_raw_type })),
        BTF_KIND_UNION => Ok(BtfType::Union(BtfTypeUnion { btf_raw_type })),
        BTF_KIND_STRUCT => Ok(BtfType::Struct(BtfTypeStruct { btf_raw_type })),
        BTF_KIND_ENUM => Ok(BtfType::Enum(BtfTypeEnum { btf_raw_type })),
        BTF_KIND_FWD => Ok(BtfType::Fwd(BtfTypeFwd { btf_raw_type })),
        BTF_KIND_TYPEDEF => Ok(BtfType::Typedef(BtfTypeTypedef { btf_raw_type })),
        BTF_KIND_VOLATILE => Ok(BtfType::Volatile(BtfTypeVolatile { btf_raw_type })),
        BTF_KIND_CONST => Ok(BtfType::Const(BtfTypeConst { btf_raw_type })),
        BTF_KIND_RESTRICT => Ok(BtfType::Restrict(BtfTypeRestrict { btf_raw_type })),
        BTF_KIND_FUNC => Ok(BtfType::Func(BtfTypeFunc { btf_raw_type })),
        BTF_KIND_FUNC_PROTO => Ok(BtfType::FuncProto(BtfTypeFuncProto { btf_raw_type })),
        BTF_KIND_VAR => Ok(BtfType::Var(BtfTypeVar { btf_raw_type })),
        BTF_KIND_DATASEC => Ok(BtfType::Datasec(BtfTypeDatasec { btf_raw_type })),
        BTF_KIND_FLOAT => Ok(BtfType::Float(BtfTypeFloat { btf_raw_type })),
        BTF_KIND_DECL_TAG => Ok(BtfType::DeclTag(BtfTypeDeclTag { btf_raw_type })),
        BTF_KIND_TYPE_TAG => Ok(BtfType::TypeTag(BtfTypeTypeTag { btf_raw_type })),
        BTF_KIND_ENUM64 => Ok(BtfType::Enum64(BtfTypeEnum64 { btf_raw_type })),
        _ => Err(binrw::Error::AssertFail {
            pos: 0,
            message: format!("Unknown BTF KIND {kind}"),
        }),
    }
}

struct BtfSplit {
    start_id: usize,
    name_start_off: usize,
    offsets: Vec<u32>,
    btf_mmap: Mmap,
    functions: HashMap<String, u32>,
}

impl BtfSplit {
    fn build(base: Option<&BtfSplit>, path: &str) -> binrw::BinResult<Self> {
        let file = std::fs::File::open(path)?;
        // copy_read_only do PROT_READ, MAP_PRIVATE mmap
        let btf_mmap = unsafe { MmapOptions::new().map_copy_read_only(&file)? };

        let mut reader = Cursor::new(&btf_mmap);
        let header = BtfHeader::read(&mut reader)?;

        let pos: u64 = (header.hdr_len + header.type_off) as u64;
        reader.seek(SeekFrom::Start(pos))?;

        let mut offsets: Vec<u32> = Vec::new();
        let mut read = 0;

        let name_start_off = (header.hdr_len + header.str_off) as usize;
        let mut functions: HashMap<String, u32> = HashMap::new();

        while read < header.type_len {
            let cur_pos = reader.stream_position()? as u32; // TODO fix usize to u32
            offsets.push(cur_pos);

            let btf_type = BtfRawType::read_ne(&mut reader)?;
            let name_off = btf_type.name_off as usize;
            let btf_kind_type = to_btf_type(btf_type)?;
            let size = btf_kind_type.kind_specific_size();

            if let BtfType::Func(_) = btf_kind_type {
                let name_pos = name_start_off + name_off;
                assert!(name_pos < btf_mmap.len());

                let ptr = btf_mmap.as_ptr() as *const c_char;
                let name_str = unsafe { CStr::from_ptr(ptr.add(name_pos)).to_str().unwrap() };
                functions.insert(name_str.to_owned(), cur_pos);
            }

            reader.seek(SeekFrom::Current(size as i64))?;

            read += 12 + (size as u32);
        }

        let start_id = match base {
            None => 1,
            Some(split) => split.start_id + split.offsets.len(),
        };

        Ok(Self {
            start_id,
            name_start_off,
            offsets,
            btf_mmap,
            functions,
        })
    }
}

impl BtfSplit {
    fn raw_type_by_id(&self, id: usize) -> binrw::BinResult<BtfRawType> {
        if id < self.start_id {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!("ID {id} smaller than start_id  {0}", self.start_id),
            });
        }

        let idx = id - self.start_id;
        if idx >= self.offsets.len() {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!("ID {id} too big"),
            });
        }

        let off = self.offsets[idx] as u64;
        let mut reader = Cursor::new(&self.btf_mmap);
        reader.seek(SeekFrom::Start(off))?;

        let btf_raw_type = BtfRawType::read_ne(&mut reader)?;
        Ok(btf_raw_type)
    }

    fn name_str(&self, btf_raw_type: &BtfRawType) -> &str {
        let pos = self.name_start_off + (btf_raw_type.name_off as usize);
        assert!(pos < self.btf_mmap.len());

        let ptr = self.btf_mmap.as_ptr() as *const c_char;
        let name_str = unsafe { CStr::from_ptr(ptr.add(pos)).to_str().unwrap() };

        name_str
    }
}

struct Btf {
    splits: Vec<BtfSplit>,
}

impl Btf {
    fn raw_type_by_id(&mut self, id: usize) -> binrw::BinResult<BtfRawType> {
        if id == 0 {
            return Ok(BtfRawType {
                name_off: 0,
                info: 0,
                union_size_type: 0,
            });
        } else {
            for split in self.splits.iter() {
                if id < split.start_id {
                    continue;
                }

                if (id - split.start_id) < split.offsets.len() {
                    return split.raw_type_by_id(id);
                }
            }
        }

        Err(binrw::Error::AssertFail {
            pos: 0,
            message: format!("ID {id} out of scope"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmlinux_btf_number_of_types() {
        // TODO: copy vmlinux to asset file to make this independent of kernel version
        let split = BtfSplit::build(None, "/sys/kernel/btf/vmlinux").unwrap();
        assert_eq!(split.offsets.len(), 140361);
    }

    #[test]
    fn test_vmlinux_btf_atomic_t() {
        let split = BtfSplit::build(None, "/sys/kernel/btf/vmlinux").unwrap();
        let atomic_typedef_raw = split.raw_type_by_id(14).unwrap();
        assert_eq!(atomic_typedef_raw.get_kind(), BTF_KIND_TYPEDEF);
        assert_eq!(split.name_str(&atomic_typedef_raw), "atomic_t");

        let atomic_typedef = to_btf_type(atomic_typedef_raw).unwrap();
        assert_eq!(atomic_typedef.kind_specific_size(), 0);
    }

    #[test]
    fn test_vmlinux_btf_char() {
        let split = BtfSplit::build(None, "/sys/kernel/btf/vmlinux").unwrap();
        let char = split.raw_type_by_id(10).unwrap();
        assert_eq!(char.get_kind(), BTF_KIND_INT);
        assert_eq!(split.name_str(&char), "char");

        let char = to_btf_type(char).unwrap();
        assert_eq!(char.kind_specific_size(), 4);
    }
}
