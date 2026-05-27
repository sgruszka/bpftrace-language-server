use binrw::BinRead;
use enum_dispatch::enum_dispatch;
use memmap2::{Mmap, MmapOptions};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;

use std::ops::Deref;

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
    str_len: u32,
}

impl BtfHeader {
    fn read<R: Read + Seek>(reader: &mut R) -> binrw::BinResult<Self> {
        let hdr = BtfHeader::read_ne(reader)?;
        if hdr.magic != 0xeb9fu16 {
            if hdr.magic == 0x9febu16 {
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

#[derive(Debug, BinRead)]
struct BtfRawArray {
    elem_type: u32,
    index_type: u32,
    nelems: u32,
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

    fn get_type_id(&self) -> u32 {
        self.union_size_type
    }
}

macro_rules! define_btf_types {
    (
        $(
            $variant:ident => $struct_name:ident
        ),* $(,)?
    ) => {
        $(
            #[derive(Debug)]
            struct $struct_name {
                btf_raw_type: BtfRawType,
                type_id: u32

            }
        )*

        #[enum_dispatch(BtfTypeTrait)]
        #[derive(Debug)]
        enum BtfType {
            $(
                $variant($struct_name),
            )*
        }
    };
}

define_btf_types! {
    Int       => BtfTypeInteger,
    Ptr       => BtfTypePointer,
    Array     => BtfTypeArray,
    Union     => BtfTypeUnion,
    Struct    => BtfTypeStruct,
    Enum      => BtfTypeEnum,
    Fwd       => BtfTypeFwd,
    Typedef   => BtfTypeTypedef,
    Volatile  => BtfTypeVolatile,
    Const     => BtfTypeConst,
    Restrict  => BtfTypeRestrict,
    Func      => BtfTypeFunc,
    FuncProto => BtfTypeFuncProto,
    Var       => BtfTypeVar,
    Datasec   => BtfTypeDatasec,
    Float     => BtfTypeFloat,
    DeclTag   => BtfTypeDeclTag,
    TypeTag   => BtfTypeTypeTag,
    Enum64    => BtfTypeEnum64,
}

fn inner_to_btf_type(btf_raw_type: BtfRawType, type_id: u32) -> Result<BtfType, binrw::Error> {
    let kind = btf_raw_type.get_kind();
    match kind {
        BTF_KIND_INT => Ok(BtfType::Int(BtfTypeInteger {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_PTR => Ok(BtfType::Ptr(BtfTypePointer {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_ARRAY => Ok(BtfType::Array(BtfTypeArray {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_UNION => Ok(BtfType::Union(BtfTypeUnion {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_STRUCT => Ok(BtfType::Struct(BtfTypeStruct {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_ENUM => Ok(BtfType::Enum(BtfTypeEnum {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_FWD => Ok(BtfType::Fwd(BtfTypeFwd {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_TYPEDEF => Ok(BtfType::Typedef(BtfTypeTypedef {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_VOLATILE => Ok(BtfType::Volatile(BtfTypeVolatile {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_CONST => Ok(BtfType::Const(BtfTypeConst {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_RESTRICT => Ok(BtfType::Restrict(BtfTypeRestrict {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_FUNC => Ok(BtfType::Func(BtfTypeFunc {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_FUNC_PROTO => Ok(BtfType::FuncProto(BtfTypeFuncProto {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_VAR => Ok(BtfType::Var(BtfTypeVar {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_DATASEC => Ok(BtfType::Datasec(BtfTypeDatasec {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_FLOAT => Ok(BtfType::Float(BtfTypeFloat {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_DECL_TAG => Ok(BtfType::DeclTag(BtfTypeDeclTag {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_TYPE_TAG => Ok(BtfType::TypeTag(BtfTypeTypeTag {
            btf_raw_type,
            type_id,
        })),
        BTF_KIND_ENUM64 => Ok(BtfType::Enum64(BtfTypeEnum64 {
            btf_raw_type,
            type_id,
        })),
        _ => Err(binrw::Error::AssertFail {
            pos: 0,
            message: format!("Unknown BTF KIND {kind}"),
        }),
    }
}

#[enum_dispatch]
trait BtfTypeTrait {
    fn kind_specific_size(&self) -> u64;
    fn string_format(&self, _split: &BtfSplit) -> (String, String) {
        ("".to_owned(), "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeInteger {
    fn kind_specific_size(&self) -> u64 {
        4
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let name = split.get_type_name(&self.btf_raw_type).to_owned();
        // TODO: bitfields ;

        (name.to_owned(), "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypePointer {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let sub_type_id = self.btf_raw_type.get_type_id();
        let sub_type_raw = split.raw_type_from_id(sub_type_id).unwrap();
        let sub_type = inner_to_btf_type(sub_type_raw, sub_type_id).unwrap();
        let (sub_prefix, sub_sufix) = sub_type.string_format(split);

        let mut prefix = sub_prefix;
        prefix.push_str(" *");

        (prefix.to_owned(), sub_sufix.to_owned())
    }
}

impl BtfTypeTrait for BtfTypeArray {
    fn kind_specific_size(&self) -> u64 {
        12
    }

    fn string_format(&self, this_split: &BtfSplit) -> (String, String) {
        let (split, mut off) = this_split.offset_from_id(self.type_id);
        off += 12;
        let raw_array = split.raw_array_by_offset(off).unwrap();
        println!(
            "ELEM TYPE {} nelems {}",
            raw_array.elem_type, raw_array.nelems
        );

        let sub_type_raw = split.raw_type_from_id(raw_array.elem_type).unwrap();
        let sub_type = inner_to_btf_type(sub_type_raw, raw_array.elem_type).unwrap();
        let (sub_prefix, sub_sufix) = sub_type.string_format(split);

        let mut sufix = sub_sufix;
        sufix.push_str(&format!("[{}]", raw_array.nelems));

        (sub_prefix, sufix.to_owned())
    }
}

impl BtfTypeTrait for BtfTypeUnion {
    fn kind_specific_size(&self) -> u64 {
        let vlen = u32_get_field!(self.btf_raw_type.info, 0, 15) as u64;
        vlen * 12
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let mut name = "union ".to_owned();
        name.push_str(split.get_type_name(&self.btf_raw_type));

        (name, "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeStruct {
    fn kind_specific_size(&self) -> u64 {
        let vlen = u32_get_field!(self.btf_raw_type.info, 0, 15) as u64;
        vlen * 12
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let mut name = "struct ".to_owned();
        name.push_str(split.get_type_name(&self.btf_raw_type));

        (name, "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeEnum {
    fn kind_specific_size(&self) -> u64 {
        let vlen = u32_get_field!(self.btf_raw_type.info, 0, 15) as u64;
        vlen * 8
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let mut name = "enum ".to_owned();
        name.push_str(split.get_type_name(&self.btf_raw_type));

        (name, "".to_owned())
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

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let sub_type_id = self.btf_raw_type.get_type_id();
        let sub_type_raw = split.raw_type_from_id(sub_type_id).unwrap();
        let sub_type = inner_to_btf_type(sub_type_raw, sub_type_id).unwrap();
        let (sub_prefix, sub_sufix) = sub_type.string_format(split);

        let prefix = match sub_type {
            BtfType::Ptr(_) => {
                let mut prefix = sub_prefix;
                prefix.push_str("const");
                prefix
            }
            _ => {
                let mut prefix = "const ".to_owned();
                prefix.push_str(&sub_prefix);
                prefix
            }
        };

        (prefix, sub_sufix.to_owned())
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

enum BtfData {
    MemoryMap(Mmap),
    Vector(Vec<u8>),
}

impl Deref for BtfData {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            BtfData::MemoryMap(mmap) => mmap.deref(),
            BtfData::Vector(vec) => vec.deref(),
        }
    }
}

impl AsRef<[u8]> for BtfData {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

struct BtfSplit {
    header: BtfHeader,
    start_id: u32,
    start_str_off: u32,
    base_split: Option<Rc<BtfSplit>>,
    offsets: Vec<u32>,
    data: BtfData,
    functions: HashMap<String, u32>,
}

impl BtfSplit {
    fn build(base: Option<Rc<BtfSplit>>, path: &str) -> binrw::BinResult<Self> {
        let (start_id, start_str_off, data, base_split) = match base {
            None => {
                let file = File::open(path)?;
                // copy_read_only do PROT_READ, MAP_PRIVATE mmap
                let btf_mmap = unsafe { MmapOptions::new().map_copy_read_only(&file)? };
                let data = BtfData::MemoryMap(btf_mmap);
                (1, 0, data, None)
            }
            Some(base_split) => {
                let vec: Vec<u8> = std::fs::read(path)?;
                let data = BtfData::Vector(vec);
                let start_id = base_split.start_id + (base_split.offsets.len() as u32);
                let start_str_off = base_split.header.str_len;
                (start_id, start_str_off, data, Some(base_split))
            }
        };

        let mut reader = Cursor::new(&data);
        let header = BtfHeader::read(&mut reader)?;

        let pos: u64 = (header.hdr_len + header.type_off) as u64;
        reader.seek(SeekFrom::Start(pos))?;

        let mut offsets: Vec<u32> = Vec::new();
        let mut read = 0;

        let mut functions: HashMap<String, u32> = HashMap::new();

        while read < header.type_len {
            let cur_pos = reader.stream_position()? as u32; // TODO fix usize to u32
            offsets.push(cur_pos);
            let type_id = start_id + (offsets.len() as u32) - 1;

            let btf_type = BtfRawType::read_ne(&mut reader)?;
            let name_off = btf_type.name_off;
            let btf_kind_type = inner_to_btf_type(btf_type, type_id)?;
            let size = btf_kind_type.kind_specific_size();

            if let BtfType::Func(_) = btf_kind_type {
                // TODO: common code with get_type_name()
                let start_off = header.hdr_len + header.str_off;
                let mut ptr = data.as_ptr() as *const c_char;
                let mut name_pos = start_off + name_off;
                if let Some(ref base_split) = base_split {
                    if name_pos < start_str_off {
                        ptr = base_split.data.as_ptr() as *const c_char;
                    } else {
                        name_pos -= start_str_off;
                    }
                }
                assert!((name_pos as usize) < data.len());

                let name = unsafe { CStr::from_ptr(ptr.add(name_pos as usize)).to_str().unwrap() };
                functions.insert(name.to_owned(), type_id);
            }

            reader.seek(SeekFrom::Current(size as i64))?;

            read += 12 + (size as u32);
        }

        Ok(Self {
            header,
            start_id,
            start_str_off,
            base_split,
            offsets,
            data,
            functions,
        })
    }
}

fn inner_raw_type_from_offset(btf_data: &BtfData, off: u32) -> binrw::BinResult<BtfRawType> {
    let mut reader = Cursor::new(&btf_data);
    reader.seek(SeekFrom::Start(off as u64))?;

    let btf_raw_type = BtfRawType::read_ne(&mut reader)?;
    Ok(btf_raw_type)
}

fn inner_raw_type_from_id(btf_split: &BtfSplit, id: u32) -> binrw::BinResult<BtfRawType> {
    if id == 0 {
        return Ok(BtfRawType {
            name_off: 0,
            info: 0,
            union_size_type: 0,
        });
    }

    if id < btf_split.start_id {
        return Err(binrw::Error::AssertFail {
            pos: 0,
            message: format!("ID {id} smaller than start_id {0}", btf_split.start_id),
        });
    }

    let idx = (id - btf_split.start_id) as usize;
    if idx >= btf_split.offsets.len() {
        return Err(binrw::Error::AssertFail {
            pos: 0,
            message: format!("ID {id} too big"),
        });
    }

    inner_raw_type_from_offset(&btf_split.data, btf_split.offsets[idx])
}

fn inner_get_type_name(btf_split: &BtfSplit, name_off: u32) -> &str {
    let start_off = btf_split.header.hdr_len + btf_split.header.str_off;
    let pos = start_off + name_off;
    assert!((pos as usize) < btf_split.data.len());

    let ptr = btf_split.data.as_ptr() as *const c_char;
    let name = unsafe { CStr::from_ptr(ptr.add(pos as usize)).to_str().unwrap() };

    name
}

impl BtfSplit {
    fn raw_type_from_id(&self, id: u32) -> binrw::BinResult<BtfRawType> {
        if id < self.start_id {
            if let Some(base_split) = &self.base_split {
                return inner_raw_type_from_id(base_split, id);
            } else {
                return Err(binrw::Error::AssertFail {
                    pos: 0,
                    message: format!("ID {id} smaller than start_id {0}", self.start_id),
                });
            }
        }

        inner_raw_type_from_id(self, id)
    }

    // fn type_from_id(&self, id: u32) -> binrw::BinResult<BtfType> {
    //     let btf_raw_type = raw_type = inner_raw
    //
    // }

    fn get_type_name(&self, btf_raw_type: &BtfRawType) -> &str {
        let name_off = btf_raw_type.name_off;
        if name_off < self.start_str_off {
            if let Some(base_split) = &self.base_split {
                return inner_get_type_name(base_split, name_off);
            } else {
                return ""; // TODO
            }
        }

        inner_get_type_name(self, name_off)
    }

    fn raw_array_by_offset(&self, off: u32) -> binrw::BinResult<BtfRawArray> {
        let mut reader = Cursor::new(&self.data);
        reader.seek(SeekFrom::Start(off as u64))?;

        let btf_raw_array = BtfRawArray::read_ne(&mut reader)?;
        Ok(btf_raw_array)
    }

    fn offset_from_id(&self, id: u32) -> (&BtfSplit, u32) {
        if id == 0 {
            return (self, 0);
        }

        if id >= self.start_id {
            let idx = (id - self.start_id) as usize;
            (self, self.offsets[idx])
        } else if let Some(base_split) = &self.base_split {
            let idx = (id - base_split.start_id) as usize;
            (base_split, base_split.offsets[idx])
        } else {
            (self, 0) // TODO
        }
    }
}

#[cfg(test)]
mod tests {
    const VMLINUX_BTF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/vmlinux.btf");
    use super::*;

    #[test]
    fn test_vmlinux_btf_number_of_types() {
        let split = BtfSplit::build(None, VMLINUX_BTF).unwrap();
        assert_eq!(split.offsets.len(), 37691);
        assert_eq!(split.functions.len(), 15944);
    }

    #[test]
    fn test_vmlinux_btf_atomic_t() {
        let split = BtfSplit::build(None, VMLINUX_BTF).unwrap();
        let atomic_typedef_raw = split.raw_type_from_id(211).unwrap();
        assert_eq!(atomic_typedef_raw.get_kind(), BTF_KIND_TYPEDEF);
        assert_eq!(split.get_type_name(&atomic_typedef_raw), "atomic_t");

        let atomic_typedef = inner_to_btf_type(atomic_typedef_raw, 211).unwrap();
        assert_eq!(atomic_typedef.kind_specific_size(), 0);
    }

    #[test]
    fn test_vmlinux_btf_char() {
        let split = BtfSplit::build(None, VMLINUX_BTF).unwrap();
        let char = split.raw_type_from_id(9).unwrap();
        assert_eq!(char.get_kind(), BTF_KIND_INT);
        assert_eq!(split.get_type_name(&char), "char");

        let char = inner_to_btf_type(char, 9).unwrap();
        assert_eq!(char.kind_specific_size(), 4);
    }

    #[test]
    fn test_vmlinux_do_brk_flags() {
        let split = BtfSplit::build(None, VMLINUX_BTF).unwrap();
        let func_id = split.functions.get("do_brk_flags").unwrap();

        let btf_raw_type = split.raw_type_from_id(*func_id).unwrap();
        assert_eq!(split.get_type_name(&btf_raw_type), "do_brk_flags");

        let type_kind = inner_to_btf_type(btf_raw_type, *func_id).unwrap();
        match type_kind {
            BtfType::Func(f) => {
                let proto_id = f.btf_raw_type.get_type_id();

                assert_eq!(proto_id, 21876);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_vmlinux_struct_kernel_param() {
        let split = BtfSplit::build(None, VMLINUX_BTF).unwrap();
        let btf_raw_type = split.raw_type_from_id(23).unwrap();

        let btf_type = inner_to_btf_type(btf_raw_type, 23).unwrap();
        let (prefix, _sufix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct kernel_param");
    }

    #[test]
    fn test_vmlinux_pointers() {
        let split = BtfSplit::build(None, VMLINUX_BTF).unwrap();

        let btf_raw_type = split.raw_type_from_id(111).unwrap();
        let btf_type = inner_to_btf_type(btf_raw_type, 111).unwrap();
        let (prefix, _sufix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct posix_acl *");

        let btf_raw_type = split.raw_type_from_id(120).unwrap();
        let btf_type = inner_to_btf_type(btf_raw_type, 120).unwrap();
        let (prefix, _sufix) = btf_type.string_format(&split);
        assert_eq!(prefix, "const struct inode_operations *");
    }

    #[test]
    fn test_vmlinux_rt2x00() {
        let base = Rc::new(BtfSplit::build(None, "/sys/kernel/btf/vmlinux").unwrap());
        let split = BtfSplit::build(Some(Rc::clone(&base)), "/sys/kernel/btf/rt2x00lib").unwrap();

        let btf_raw_type = base.raw_type_from_id(1708).unwrap();
        let btf_type = inner_to_btf_type(btf_raw_type, 1708).unwrap();
        let (prefix, _sufix) = btf_type.string_format(&base);
        assert_eq!(prefix, "const struct device *");

        let btf_raw_type = split.raw_type_from_id(140493).unwrap();
        let btf_type = inner_to_btf_type(btf_raw_type, 140493).unwrap();
        let (prefix, _sufix) = btf_type.string_format(&split);
        assert_eq!(prefix, "const struct device *const");

        let btf_raw_type = split.raw_type_from_id(140494).unwrap();
        let btf_type = inner_to_btf_type(btf_raw_type, 140494).unwrap();
        let (prefix, _sufix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct device *const");
    }

    #[test]
    fn test_vmlinux_array() {
        let base = Rc::new(BtfSplit::build(None, "/sys/kernel/btf/vmlinux").unwrap());
        let split = BtfSplit::build(Some(Rc::clone(&base)), "/sys/kernel/btf/rt2x00lib").unwrap();

        let btf_raw_type = split.raw_type_from_id(140495).unwrap();
        let btf_type = inner_to_btf_type(btf_raw_type, 140495).unwrap();
        let (prefix, sufix) = btf_type.string_format(&split);
        assert_eq!(prefix, "int");
        assert_eq!(sufix, "[10]");

        let btf_raw_type = split.raw_type_from_id(140496).unwrap();
        let btf_type = inner_to_btf_type(btf_raw_type, 140496).unwrap();
        let (prefix, sufix) = btf_type.string_format(&split);
        assert_eq!(prefix, "const struct device *");
        assert_eq!(sufix, "[2]");

        // TODO test array[N][M]
    }
}
