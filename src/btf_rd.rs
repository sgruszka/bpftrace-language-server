use binrw::BinRead;
use enum_dispatch::enum_dispatch;
use memmap2::{Mmap, MmapOptions};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use std::ops::Deref;

use crate::log_mod::{self, BTFRD};
use crate::{log_dbg, log_err};
use std::ffi::CStr;
use std::os::raw::c_char;

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

const BTF_KIND_VOID: u32 = 0;
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
    _index_type: u32,
    nelems: u32,
}

#[derive(Debug, BinRead)]
struct BtfRawParam {
    name_off: u32,
    type_id: u32,
}

#[derive(Debug, BinRead)]
struct BtfRawMember {
    name_off: u32,
    type_id: u32,
    offset: u32,
}

#[derive(Debug, BinRead)]
struct BtfRawInt {
    encoding: u32,
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

    fn get_kind_flag(&self) -> u32 {
        u32_get_field!(self.info, 31, 31)
    }

    fn get_vlen(&self) -> u32 {
        u32_get_field!(self.info, 0, 15)
    }

    fn get_type_id(&self) -> u32 {
        self.union_size_type
    }

    fn get_size(&self) -> u32 {
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
            #[allow(dead_code)]
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
    Void      => BtfTypeVoid,
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
        BTF_KIND_VOID => Ok(BtfType::Void(BtfTypeVoid {
            btf_raw_type,
            type_id,
        })),
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
    fn string_format(&self, _split: &BtfSplit) -> (String, String);
}

impl BtfTypeTrait for BtfTypeVoid {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, _split: &BtfSplit) -> (String, String) {
        ("void".to_owned(), "".to_owned())
    }
}
impl BtfTypeTrait for BtfTypeInteger {
    fn kind_specific_size(&self) -> u64 {
        4
    }

    fn string_format(&self, this_split: &BtfSplit) -> (String, String) {
        let name = this_split.get_type_name(&self.btf_raw_type).to_owned();
        let size = self.btf_raw_type.get_size();

        let (split, mut off) = this_split.offset_from_id(self.type_id);
        off += 12;

        let raw_int_res: binrw::BinResult<BtfRawInt> = split.read_raw_struct(off);
        let raw_int = match raw_int_res {
            Ok(ri) => ri,
            Err(e) => {
                log_err!("Failed to read raw_int at {off} with {e}");
                return ("".to_owned(), "".to_owned());
            }
        };

        let bits = raw_int.encoding & 0xffu32;
        let suffix = if bits > 0 && bits < size {
            format!(":{bits}")
        } else {
            "".to_owned()
        };

        (name.to_owned(), suffix)
    }
}

impl BtfTypeTrait for BtfTypePointer {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let sub_type_id = self.btf_raw_type.get_type_id();
        let sub_type = match split.type_from_id(sub_type_id) {
            Ok(t) => t,
            Err(e) => {
                log_err!("Failed to get type for id {} with error {}", sub_type_id, e);
                return ("".to_owned(), "".to_owned());
            }
        };
        let (sub_prefix, sub_suffix) = sub_type.string_format(split);

        let mut prefix = sub_prefix;
        let mut suffix;
        match sub_type {
            BtfType::FuncProto(_) => {
                prefix.push_str(" (*");
                suffix = ")".to_string();
                suffix.push_str(&sub_suffix);
            }
            _ => {
                prefix.push_str(" *");
                suffix = sub_suffix;
            }
        }

        (prefix.to_owned(), suffix.to_owned())
    }
}

impl BtfTypeTrait for BtfTypeArray {
    fn kind_specific_size(&self) -> u64 {
        12
    }

    fn string_format(&self, this_split: &BtfSplit) -> (String, String) {
        let (split, mut off) = this_split.offset_from_id(self.type_id);
        off += 12;

        let raw_array_res: binrw::BinResult<BtfRawArray> = split.read_raw_struct(off);
        let raw_array = match raw_array_res {
            Ok(ra) => ra,
            Err(e) => {
                log_err!("Failed to read raw_array at {off} with {e}");
                return ("".to_owned(), "".to_owned());
            }
        };

        let sub_type = match split.type_from_id(raw_array.elem_type) {
            Ok(t) => t,
            Err(e) => {
                log_err!(
                    "Failed to get type for id {} with error {}",
                    raw_array.elem_type,
                    e
                );
                return ("".to_owned(), "".to_owned());
            }
        };
        let (sub_prefix, sub_suffix) = sub_type.string_format(split);

        let mut suffix = sub_suffix;
        suffix.push_str(&format!("[{}]", raw_array.nelems));

        (sub_prefix, suffix.to_owned())
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

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let flag = self.btf_raw_type.get_kind_flag();
        let mut name = if flag == 0 {
            "struct ".to_owned()
        } else {
            "union ".to_owned()
        };

        name.push_str(split.get_type_name(&self.btf_raw_type));
        (name, "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeTypedef {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let name = split.get_type_name(&self.btf_raw_type).to_owned();
        (name.to_owned(), "".to_owned())
    }
}

fn ptr_qualifier_string_format(
    split: &BtfSplit,
    sub_type_id: u32,
    qualifier: &str,
) -> (String, String) {
    let sub_type = match split.type_from_id(sub_type_id) {
        Ok(t) => t,
        Err(e) => {
            log_err!("Failed to get type for id {} with error {}", sub_type_id, e);
            return ("".to_owned(), "".to_owned());
        }
    };

    let (sub_prefix, sub_suffix) = sub_type.string_format(split);

    let prefix = match sub_type {
        BtfType::Ptr(_) => {
            let mut prefix = sub_prefix;
            prefix.push_str(qualifier);
            prefix
        }
        _ => {
            let mut prefix = qualifier.to_owned();
            prefix.push_str(" ");
            prefix.push_str(&sub_prefix);
            prefix
        }
    };

    (prefix, sub_suffix.to_owned())
}

impl BtfTypeTrait for BtfTypeVolatile {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let sub_type_id = self.btf_raw_type.get_type_id();
        ptr_qualifier_string_format(split, sub_type_id, "volatile")
    }
}

impl BtfTypeTrait for BtfTypeConst {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let sub_type_id = self.btf_raw_type.get_type_id();
        ptr_qualifier_string_format(split, sub_type_id, "const")
    }
}

impl BtfTypeTrait for BtfTypeRestrict {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let sub_type_id = self.btf_raw_type.get_type_id();
        ptr_qualifier_string_format(split, sub_type_id, "restrict")
    }
}

impl BtfTypeTrait for BtfTypeFunc {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, _split: &BtfSplit) -> (String, String) {
        log_err!("string_format() implemented for BtfTypeFunc");
        ("".to_owned(), "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeFuncProto {
    fn kind_specific_size(&self) -> u64 {
        let vlen = self.btf_raw_type.get_vlen() as u64;
        vlen * 8
    }

    fn string_format(&self, this_split: &BtfSplit) -> (String, String) {
        let (split, mut off) = this_split.offset_from_id(self.type_id);
        off += 12;

        let mut func_proto = "(".to_owned();

        let vlen = self.btf_raw_type.get_vlen();
        for p in 0..vlen {
            let raw_param_res: binrw::BinResult<BtfRawParam> = split.read_raw_struct(off);
            off += 8;
            let raw_param = match raw_param_res {
                Ok(rp) => rp,
                Err(e) => {
                    log_err!("Failed to read raw_param at {off} with {e}");
                    return ("".to_owned(), "".to_owned());
                }
            };

            let sub_type = match split.type_from_id(raw_param.type_id) {
                Ok(t) => t,
                Err(e) => {
                    log_err!(
                        "Failed to get type for id {} with error {}",
                        raw_param.type_id,
                        e
                    );
                    return ("".to_owned(), "".to_owned());
                }
            };
            let (sub_prefix, sub_suffix) = sub_type.string_format(this_split);

            let name = this_split.get_name(raw_param.name_off);

            if !name.is_empty() || !sub_suffix.is_empty() {
                func_proto.push_str(&format!("{} {}{}", sub_prefix, name, sub_suffix));
            } else {
                func_proto.push_str(&sub_prefix);
            };

            if p < vlen - 1 {
                func_proto.push_str(", ");
            }
        }

        func_proto.push_str(")");

        let ret_type_id = self.btf_raw_type.get_type_id();

        let ret_sub_type = match split.type_from_id(ret_type_id) {
            Ok(t) => t,
            Err(e) => {
                log_err!("Failed to get type for id {} with error {}", ret_type_id, e);
                return ("".to_owned(), "".to_owned());
            }
        };
        let (mut ret_type, ret_suffix) = ret_sub_type.string_format(this_split);
        if !ret_suffix.is_empty() {
            ret_type.push_str(" ");
            ret_type.push_str(&ret_suffix);
        }

        (ret_type, func_proto.to_owned())
    }
}

impl BtfTypeTrait for BtfTypeVar {
    fn kind_specific_size(&self) -> u64 {
        4
    }

    fn string_format(&self, _split: &BtfSplit) -> (String, String) {
        log_err!("string_format() implemented for BtfTypeVar");
        ("".to_owned(), "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeDatasec {
    fn kind_specific_size(&self) -> u64 {
        let vlen = self.btf_raw_type.get_vlen() as u64;
        vlen * 12
    }

    fn string_format(&self, _split: &BtfSplit) -> (String, String) {
        log_err!("string_format() implemented for BtfTypeDatasec");
        ("".to_owned(), "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeFloat {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, _split: &BtfSplit) -> (String, String) {
        log_err!("string_format() implemented for BtfTypeFloat");
        ("".to_owned(), "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeDeclTag {
    fn kind_specific_size(&self) -> u64 {
        4
    }

    fn string_format(&self, _split: &BtfSplit) -> (String, String) {
        log_err!("string_format() implemented for BtfTypeDeclTag");
        ("".to_owned(), "".to_owned())
    }
}

impl BtfTypeTrait for BtfTypeTypeTag {
    fn kind_specific_size(&self) -> u64 {
        0
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let sub_type_id = self.btf_raw_type.get_type_id();
        let sub_type = match split.type_from_id(sub_type_id) {
            Ok(t) => t,
            Err(e) => {
                log_err!("Failed to get type for id {sub_type_id} with error {e}");
                return ("".to_owned(), "".to_owned());
            }
        };
        let (sub_prefix, sub_suffix) = sub_type.string_format(split);

        let name = split.get_type_name(&self.btf_raw_type);

        let mut prefix = sub_prefix;
        prefix.push_str(" __");
        prefix.push_str(name);

        (prefix.to_owned(), sub_suffix.to_owned())
    }
}

impl BtfTypeTrait for BtfTypeEnum64 {
    fn kind_specific_size(&self) -> u64 {
        let vlen = self.btf_raw_type.get_vlen() as u64;
        vlen * 12
    }

    fn string_format(&self, split: &BtfSplit) -> (String, String) {
        let mut name = "enum ".to_owned();
        name.push_str(split.get_type_name(&self.btf_raw_type));

        (name, "".to_owned())
    }
}

// For struct/union fields, function parameters, etc ...
#[derive(Clone)]
pub struct BtfVariable {
    pub name: String,
    pub type_id: u32,
    pub bits: Option<u32>,
}

impl BtfTypeFunc {
    fn parameters(&self, this_split: &BtfSplit) -> Vec<BtfVariable> {
        let func_proto_id = self.btf_raw_type.get_type_id();

        let (split, mut off) = this_split.offset_from_id(func_proto_id);

        let raw_func_proto_res: binrw::BinResult<BtfRawType> = split.read_raw_struct(off);
        off += 12;
        let raw_func_proto = match raw_func_proto_res {
            Ok(rfp) => rfp,
            Err(e) => {
                log_err!("Failed to read raw_func_proto at {off} with {e}");
                return Vec::new();
            }
        };

        let mut params: Vec<BtfVariable> = Vec::new();

        let vlen = raw_func_proto.get_vlen();
        for _ in 0..vlen {
            let raw_param_res: binrw::BinResult<BtfRawParam> = split.read_raw_struct(off);
            off += 8;
            let raw_param = match raw_param_res {
                Ok(rp) => rp,
                Err(e) => {
                    log_err!("Failed to read raw_param at {off} with {e}");
                    return Vec::new();
                }
            };

            let name = this_split.get_name(raw_param.name_off).to_owned();
            let type_id = raw_param.type_id;

            params.push(BtfVariable {
                name,
                type_id,
                bits: None,
            });
        }

        params
    }
}

fn composite_members(this_split: &BtfSplit, type_id: u32, vlen: u32) -> Vec<BtfVariable> {
    let (split, mut off) = this_split.offset_from_id(type_id);
    off += 12;

    let mut members: Vec<BtfVariable> = Vec::new();

    for _ in 0..vlen {
        let raw_member_res: binrw::BinResult<BtfRawMember> = split.read_raw_struct(off);
        off += 12;
        let raw_member = match raw_member_res {
            Ok(rm) => rm,
            Err(e) => {
                log_err!("Failed to read raw_member at {off} with {e}");
                return Vec::new();
            }
        };

        let name = this_split.get_name(raw_member.name_off).to_owned();

        let bitfield_size = raw_member.offset >> 24;
        let bits = if bitfield_size > 0 {
            Some(bitfield_size)
        } else {
            None
        };

        members.push(BtfVariable {
            name,
            type_id: raw_member.type_id,
            bits,
        });
    }

    members
}

impl BtfTypeStruct {
    fn members(&self, this_split: &BtfSplit) -> Vec<BtfVariable> {
        composite_members(this_split, self.type_id, self.btf_raw_type.get_vlen())
    }
}

impl BtfTypeUnion {
    fn members(&self, this_split: &BtfSplit) -> Vec<BtfVariable> {
        composite_members(this_split, self.type_id, self.btf_raw_type.get_vlen())
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

pub struct BtfSplit {
    header: BtfHeader,
    start_id: u32,
    start_str_off: u32,
    base_split: Option<Arc<BtfSplit>>,
    offsets: Vec<u32>,
    data: BtfData,
    functions: HashMap<String, u32>,
    structs: HashMap<String, u32>,
    unions: HashMap<String, u32>,
}

pub type Btf = BtfSplit;

impl BtfSplit {
    fn build(base: Option<Arc<BtfSplit>>, path: &str) -> binrw::BinResult<Self> {
        let (start_id, start_str_off, data, base_split) = match base {
            None => {
                let file = File::open(path)?;

                let data =
                    // copy_read_only do PROT_READ, MAP_PRIVATE mmap
                    if let Ok(btf_mmap) = unsafe { MmapOptions::new().map_copy_read_only(&file) } {
                        BtfData::MemoryMap(btf_mmap)
                    } else {
                        let vec: Vec<u8> = std::fs::read(path)?;
                        BtfData::Vector(vec)
                    };

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
        let mut structs: HashMap<String, u32> = HashMap::new();
        let mut unions: HashMap<String, u32> = HashMap::new();

        while read < header.type_len {
            let cur_pos = reader.stream_position()? as u32;
            offsets.push(cur_pos);
            let type_id = start_id + (offsets.len() as u32) - 1;

            let btf_type = BtfRawType::read_ne(&mut reader)?;
            let name_off = btf_type.name_off;
            let btf_kind_type = inner_to_btf_type(btf_type, type_id)?;
            let size = btf_kind_type.kind_specific_size();

            let get_type_name = || {
                let name = if name_off < start_str_off {
                    if let Some(ref base_split) = base_split {
                        inner_get_name(base_split, name_off)
                    } else {
                        return Err(binrw::Error::AssertFail {
                            pos: 0,
                            message: format!("Failed to resolve name offset {} ", name_off),
                        });
                    }
                } else {
                    let start_off = header.hdr_len + header.str_off;
                    let name_pos = start_off + name_off - start_str_off;
                    let ptr = data.as_ptr() as *const c_char;
                    assert!((name_pos as usize) < data.len());

                    unsafe { CStr::from_ptr(ptr.add(name_pos as usize)).to_str().unwrap() }
                };

                Ok(name)
            };

            match btf_kind_type {
                BtfType::Func(_) => {
                    let name = get_type_name()?;
                    if !name.is_empty() {
                        functions.insert(name.to_owned(), type_id);
                    }
                }

                BtfType::Struct(_) => {
                    let name = get_type_name()?;
                    if !name.is_empty() {
                        structs.insert(name.to_owned(), type_id);
                    }
                }
                BtfType::Union(_) => {
                    let name = get_type_name()?;
                    if !name.is_empty() {
                        unions.insert(name.to_owned(), type_id);
                    }
                }
                _ => (),
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
            structs,
            unions,
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

fn inner_get_name(btf_split: &BtfSplit, name_off: u32) -> &str {
    let start_off = btf_split.header.hdr_len + btf_split.header.str_off;
    let pos = start_off + name_off;
    assert!((pos as usize) < btf_split.data.len());

    let ptr = btf_split.data.as_ptr() as *const c_char;
    let name = unsafe { CStr::from_ptr(ptr.add(pos as usize)).to_str().unwrap() };

    name
}

impl BtfSplit {
    fn raw_type_from_id(&self, id: u32) -> binrw::BinResult<BtfRawType> {
        if id == 0 {
            return inner_raw_type_from_id(self, id);
        } else if id < self.start_id {
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

    fn type_from_id(&self, id: u32) -> binrw::BinResult<BtfType> {
        let btf_raw_type = self.raw_type_from_id(id)?;
        inner_to_btf_type(btf_raw_type, id)
    }

    fn get_type_name(&self, btf_raw_type: &BtfRawType) -> &str {
        let name_off = btf_raw_type.name_off;
        self.get_name(name_off)
    }

    fn get_name(&self, name_off: u32) -> &str {
        if name_off < self.start_str_off {
            if let Some(base_split) = &self.base_split {
                return inner_get_name(base_split, name_off);
            } else {
                return ""; // TODO
            }
        }

        inner_get_name(self, name_off - self.start_str_off)
    }

    fn read_raw_struct<T>(&self, off: u32) -> binrw::BinResult<T>
    where
        T: BinRead,
        for<'a> T::Args<'a>: Default,
    {
        let mut reader = Cursor::new(&self.data);
        reader.seek(SeekFrom::Start(off as u64))?;

        let btf_raw_struct = T::read_ne(&mut reader)?;
        Ok(btf_raw_struct)
    }

    fn offset_from_id(&self, id: u32) -> (&BtfSplit, u32) {
        assert!(id != 0);

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

    fn find_function(&self, func_name: &str) -> Option<BtfTypeFunc> {
        let id = self.functions.get(func_name)?;

        let btf_type = match self.type_from_id(*id) {
            Ok(t) => t,
            Err(e) => {
                log_err!("Failed to get type for id {} with error {}", *id, e);
                return None;
            }
        };

        match btf_type {
            BtfType::Func(f) => Some(f),
            _ => None,
        }
    }
}

static VMLINUX_BTF: OnceLock<Option<Arc<Btf>>> = OnceLock::new();

fn btf_setup_vmlinux_btf() -> Option<Arc<Btf>> {
    let vmlinux_btf = if cfg!(test) && !cfg!(feature = "live_btf_tests") {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/vmlinux.btf")
    } else {
        "/sys/kernel/btf/vmlinux"
    };

    match BtfSplit::build(None, vmlinux_btf) {
        Ok(btf) => {
            log_dbg!(BTFRD, "Loaded vmlinux BTF from {}", vmlinux_btf);
            Some(Arc::new(btf))
        }
        Err(e) => {
            log_err!("Failed to build vmlinux BTF from {vmlinux_btf} with error {e}");
            None
        }
    }
}

static MODULE_BTF_MAP: LazyLock<Mutex<HashMap<String, Arc<Btf>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn btf_module_get(module: &str) -> Option<Arc<Btf>> {
    log_dbg!(BTFRD, "Looking for btf for module: {}", module);

    let module_btf = if cfg!(test) && !cfg!(feature = "live_btf_tests") {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/");
        path.to_owned() + module + ".btf"
    } else {
        let path = "/sys/kernel/btf/";
        path.to_owned() + module
    };

    let Some(vmlinux_btf_ref) = VMLINUX_BTF.get_or_init(btf_setup_vmlinux_btf) else {
        log_err!("Failed to setup vmlinux BTF");
        return None;
    };

    if module.is_empty() || module == "vmlinux" {
        return Some(vmlinux_btf_ref.clone());
    }

    let mut module_btf_map = MODULE_BTF_MAP.lock().unwrap();

    if let Some(btf) = module_btf_map.get(module) {
        Some(btf.clone())
    } else {
        match BtfSplit::build(Some(Arc::clone(vmlinux_btf_ref)), &module_btf) {
            Ok(split) => {
                log_dbg!(BTFRD, "Loaded BTF from {module_btf}");

                let btf = Arc::new(split);
                module_btf_map.insert(module.to_string(), btf.clone());
                Some(btf.clone())
            }
            Err(e) => {
                log_err!("Failed to build module {module} BTF from {module_btf} with error {e}");
                None
            }
        }
    }
}

pub struct BtfFunction {
    pub name: String,
    pub full_name: String,
    pub args: Vec<BtfVariable>,
    type_id: u32,
    ret_type_id: u32,
    proto_id: u32,
}

// #[allow(clippy::needless_range_loop)]
// fn func_proto_str(item: &Reso) -> String {
//     let mut s = String::new();
//     let params = &item.children_vec;
//
//     let mut l = params.len();
//
//     if l > 0 && params[l - 1].name == "retval" {
//         s.push_str(&params[l - 1].type_vec.join(" ").to_string());
//         l -= 1;
//     } else {
//         s.push_str("void");
//     }
//
//     s.push_str(" ");
//     s.push_str(&item.name);
//
//     s.push_str("(");
//     for i in 0..l {
//         let p = &params[i];
//
//         s.push_str(&p.type_vec.join(" "));
//         if !s.ends_with("*") {
//             s.push_str(" ");
//         }
//         s.push_str(&p.name);
//         if i < l - 1 {
//             s.push_str(", ")
//         }
//     }
//     s.push_str(");");
//
//     s
// }

pub fn btf_resolve_func(btf: &Btf, func_name: &str) -> Option<BtfFunction> {
    log_dbg!(BTFRD, "Looking for function {}", func_name);

    let func = btf.find_function(func_name)?;
    let name = btf.get_type_name(&func.btf_raw_type);

    let func_proto_id = func.btf_raw_type.get_type_id();
    let func_proto_raw = btf.raw_type_from_id(func_proto_id).ok()?;
    // TODO print error
    let ret_type_id = func_proto_raw.get_type_id();
    let func_proto = inner_to_btf_type(func_proto_raw, func_proto_id).ok()?;
    let (ret_type, args) = func_proto.string_format(btf);

    let mut proto = String::new();
    proto.push_str(&ret_type);
    proto.push_str(" ");
    proto.push_str(name);
    proto.push_str(&args);

    let args = func.parameters(btf);
    let name = name.to_string();

    Some(BtfFunction {
        name,
        full_name: proto,
        args,
        type_id: func.type_id,
        proto_id: func_proto_id,
        ret_type_id,
    })
}

#[allow(unused)]
pub struct BtfName {
    type_name: String,
    full_name: String,
}

pub struct BtfResolvedType {
    pub type_id: u32,
    pub actual_type_id: u32,
    pub type_prefix: String,
    pub type_suffix: String,
    pub actual_type: Option<BtfComposite>,
}

// Struct/Union
pub struct BtfComposite {
    #[allow(unused)]
    type_id: u32,
    pub type_name: String,
    pub members: Vec<BtfVariable>,
}

pub fn btf_resolve_type(btf: &Btf, type_id: u32) -> Option<BtfResolvedType> {
    let mut is_composite = false;

    let btf_type = match btf.type_from_id(type_id) {
        Ok(t) => t,
        Err(e) => {
            log_err!("Failed to get type for id {} with error {}", type_id, e);
            return None;
        }
    };

    // TODO: for BtfTypeFwd we do not have actual type_id (struct or union),
    // we will need to resovle by name

    let mut id = type_id;
    loop {
        let btf_sub_type = match btf.type_from_id(id) {
            Ok(t) => t,
            Err(e) => {
                log_err!("Failed to get type for id {} with error {}", id, e);
                return None;
            }
        };

        let sub_id = match btf_sub_type {
            BtfType::Const(c) => c.btf_raw_type.get_type_id(),
            BtfType::Volatile(v) => v.btf_raw_type.get_type_id(),
            BtfType::Restrict(r) => r.btf_raw_type.get_type_id(),
            BtfType::Ptr(p) => p.btf_raw_type.get_type_id(),
            BtfType::Typedef(td) => td.btf_raw_type.get_type_id(),
            BtfType::TypeTag(tt) => tt.btf_raw_type.get_type_id(),
            // TODO: Func / Func Proto // TypeTag ...
            BtfType::Array(_) => {
                let (split, mut off) = btf.offset_from_id(id);
                off += 12;

                let raw_array_res: binrw::BinResult<BtfRawArray> = split.read_raw_struct(off);
                let raw_array = match raw_array_res {
                    Ok(ra) => ra,
                    Err(e) => {
                        log_err!("Failed to read raw_array at {off} with {e}");
                        return None;
                    }
                };
                raw_array.elem_type
            }
            BtfType::Struct(_) => {
                is_composite = true;
                break;
            }
            BtfType::Union(_) => {
                is_composite = true;
                break;
            }
            _ => break,
        };
        id = sub_id;
    }

    let actual_type = if is_composite {
        let comp_type = match btf.type_from_id(id) {
            Ok(t) => t,
            Err(e) => {
                log_err!("Failed to get type for id {} with error {}", id, e);
                return None;
            }
        };

        let (prefix, suffix) = comp_type.string_format(btf);
        assert_eq!(suffix, "");

        let members = match comp_type {
            BtfType::Struct(s) => s.members(btf),
            BtfType::Union(u) => u.members(btf),
            _ => panic!(),
        };

        Some(BtfComposite {
            type_id: id,
            type_name: prefix,
            members,
        })
    } else {
        None
    };

    let (type_prefix, type_suffix) = btf_type.string_format(btf);

    Some(BtfResolvedType {
        type_id,
        actual_type_id: id,
        type_prefix,
        type_suffix,
        actual_type,
    })
}

pub fn btf_resolve_struct(btf: &Btf, name: &str) -> Option<BtfResolvedType> {
    let type_id = btf.structs.get(name)?;
    btf_resolve_type(btf, *type_id)
}

pub fn btf_resolve_union(btf: &Btf, name: &str) -> Option<BtfResolvedType> {
    let type_id = btf.unions.get(name)?;
    btf_resolve_type(btf, *type_id)
}

#[allow(unused)]
pub fn btf_variable_name(btf: &Btf, var: &BtfVariable) -> Option<BtfName> {
    log_dbg!(
        BTFRD,
        "Looking for name of variable {} with id {} ",
        var.name,
        var.type_id
    );

    let btf_type = btf.type_from_id(var.type_id).ok()?;
    let (type_prefix, type_suffix) = btf_type.string_format(btf);

    // TODO: correct push spaces for different types
    let type_name = type_prefix.clone() + &type_suffix;

    let space = if !type_prefix.ends_with("*") { " " } else { "" };
    let full_name = type_prefix + space + &var.name + &type_suffix;

    Some(BtfName {
        type_name,
        full_name,
    })
}

fn is_pointer_type(btf: &Btf, type_id: u32) -> bool {
    let Ok(btf_type) = btf.type_from_id(type_id) else {
        return false;
    };

    // TODO limit to struct or union pointers ?
    matches!(btf_type, BtfType::Ptr(_))
}

fn chain_str_to_tokens(names_chain: &str) -> Vec<&str> {
    let mut res: Vec<&str> = Vec::new();

    let mut start_idx = 0;
    let mut end_idx = 0;

    for (i, c) in names_chain.char_indices() {
        match c {
            '.' => {
                res.push(&names_chain[start_idx..i]);
                res.push(".");
                start_idx = i + 1;
            }
            '-' => {
                res.push(&names_chain[start_idx..i]);
                start_idx = i + 1;
            }
            '>' => {
                res.push("->");
                start_idx = i + 1;
            }
            _ => end_idx = i,
        };
    }

    if end_idx != 0 && start_idx <= end_idx {
        res.push(&names_chain[start_idx..=end_idx]);
    }

    res
}

fn find_member(btf: &Btf, composite: &BtfComposite, member_name: &str) -> Option<BtfVariable> {
    for m in composite.members.iter() {
        if m.name == *member_name {
            return Some(m.clone());
        }

        if m.name.is_empty() {
            let Some(anonymous_type) = btf_resolve_type(btf, m.type_id) else {
                continue;
            };

            let Some(actual_type) = anonymous_type.actual_type else {
                continue;
            };

            if let Some(member) = find_member(btf, &actual_type, member_name) {
                return Some(member.clone());
            }
        }
    }

    None
}

fn iterate_over_names_chain(
    btf: &Btf,
    first_var: &BtfVariable,
    name_chain: &Vec<&str>,
) -> Option<BtfVariable> {
    let mut names_iter = name_chain.iter();

    let first_name = names_iter.next()?;
    assert_eq!(*first_name, first_var.name);

    // Handle struct/union members: use -> for pointrs and . for direct access
    let mut cur_var = first_var.clone();
    while let Some(op) = names_iter.next() {
        let is_pointer = is_pointer_type(btf, cur_var.type_id);

        if *op == "->" {
            if !is_pointer {
                return None;
            }
        } else if *op == "." {
            // Newer bpftrace allow dereferencing pointers using dot
        } else {
            return None;
        }

        let member_name = if let Some(name) = names_iter.next() {
            name
        } else {
            if name_chain.last() == Some(&"->") || name_chain.last() == Some(&".") {
                break;
            }
            return None;
        };

        let cur_type = btf_resolve_type(btf, cur_var.type_id)?;
        let composite = cur_type.actual_type?;
        let member = find_member(btf, &composite, member_name)?;

        cur_var = member.clone();
    }

    Some(cur_var)
}

pub fn btf_iterate_members(
    btf: &Btf,
    first_field: &str,
    comp: &BtfComposite,
    name_chain_str: &str,
) -> Option<(BtfVariable, BtfResolvedType)> {
    if !name_chain_str.starts_with("args.") && !name_chain_str.starts_with("args->") {
        return None;
    }
    let mut name_chain = chain_str_to_tokens(name_chain_str);
    if name_chain.len() < 4 {
        return None;
    }

    name_chain.remove(0); // 'args'
    name_chain.remove(0); // '.' or '->'

    let first_name = name_chain[0];
    if first_name != first_field {
        return None;
    }
    name_chain.remove(0); // 'first_field

    let first_op = name_chain[0];
    if first_op != "->" && first_op != "." {
        return None;
    }
    name_chain.remove(0);

    let cur_var = if name_chain.is_empty() {
        BtfVariable {
            name: first_field.to_string(),
            // We don't have pointer type_id, use struct/union type_id
            type_id: comp.type_id,
            bits: None,
        }
    } else {
        let second_name = name_chain[0];
        let first_param = comp.members.iter().find(|p| p.name == *second_name)?;
        iterate_over_names_chain(btf, first_param, &name_chain)?
    };

    let cur_type = btf_resolve_type(btf, cur_var.type_id)?;

    Some((cur_var, cur_type))
}

pub fn btf_iterate_function_args(
    btf: &Btf,
    func: &BtfFunction,
    name_chain_str: &str,
) -> Option<(BtfVariable, BtfResolvedType)> {
    let mut name_chain = chain_str_to_tokens(name_chain_str);

    // Support only args. , retval() , retval as prefixes for name chain
    if !name_chain_str.starts_with("args") && !name_chain_str.starts_with("retval") {
        return None;
    }

    let mut is_retval = false;
    if name_chain.len() == 1 {
        if name_chain[0] == "retval()" || name_chain[0] == "retval" {
            is_retval = true;
            name_chain.remove(0);
        } else {
            return None;
        }
    } else if name_chain.len() >= 2 {
        if name_chain[0] == "retval()" || name_chain[0] == "retval" {
            is_retval = true;
            name_chain.remove(0);
            name_chain.remove(0); // -> or .
        } else if name_chain[0] == "args" && (name_chain[1] == "." || name_chain[1] == "->") {
            name_chain.remove(0);
            name_chain.remove(0); // .
        } else {
            return None;
        }
    } else {
        return None;
    }

    if is_retval {
        let cur_type = btf_resolve_type(btf, func.ret_type_id)?;
        if let Some(first_name) = name_chain.first() {
            let actual_type = cur_type.actual_type?;
            if let Some(first_param) = find_member(btf, &actual_type, first_name) {
                let cur_var = iterate_over_names_chain(btf, &first_param, &name_chain)?;
                let cur_type = btf_resolve_type(btf, cur_var.type_id)?;
                return Some((cur_var, cur_type));
            }
        } else {
            let cur_var = BtfVariable {
                type_id: func.ret_type_id,
                name: "retval".to_owned(),
                bits: None,
            };
            return Some((cur_var, cur_type));
        }
    } else if let Some(first_name) = name_chain.first() {
        if let Some(first_param) = func.args.iter().find(|p| p.name == *first_name) {
            let cur_var = iterate_over_names_chain(btf, first_param, &name_chain)?;
            let cur_type = btf_resolve_type(btf, cur_var.type_id)?;
            return Some((cur_var, cur_type));
        }
    } else {
        // Convert BtfFunction to BtfResolvedType
        let cur_var = BtfVariable {
            type_id: func.type_id,
            name: func.name.clone(),
            bits: None,
        };
        let func_args = BtfComposite {
            type_id: func.proto_id,
            type_name: func.full_name.clone(),
            members: func.args.clone(),
        };
        let cur_type = BtfResolvedType {
            type_id: func.type_id,
            actual_type_id: func.proto_id,
            type_prefix: func.name.clone(),
            type_suffix: func.full_name.clone(),
            actual_type: Some(func_args),
        };
        return Some((cur_var, cur_type));
    }

    None
}

#[cfg(test)]
mod tests {
    const VMLINUX_BTF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/vmlinux.btf");
    use super::*;

    #[test]
    fn test_load_module() {
        let btf1 = btf_module_get("vmlinux");
        assert!(btf1.is_some());

        let btf2 = btf_module_get("Xblabla713h");
        assert!(btf2.is_none());
    }

    #[test]
    fn test_chain_str_to_tokens() {
        assert!(chain_str_to_tokens("args") == vec!["args"]);
        assert!(chain_str_to_tokens("args.") == vec!["args", "."]);
        assert!(chain_str_to_tokens("xxx->yyy") == vec!["xxx", "->", "yyy"]);
        assert!(chain_str_to_tokens("a.b.c.d") == vec!["a", ".", "b", ".", "c", ".", "d"]);
        assert!(
            chain_str_to_tokens("args.f1.f2->f3") == vec!["args", ".", "f1", ".", "f2", "->", "f3"]
        );
    }
    #[test]
    fn test_vmlinux_btf_number_of_types() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        assert_eq!(split.offsets.len(), 37691);
        assert_eq!(split.functions.len(), 15944);
        assert_eq!(split.structs.len(), 2448);
        assert_eq!(split.unions.len(), 59);
    }

    #[test]
    fn test_vmlinux_btf_atomic_t() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        let atomic_typedef_raw = split.raw_type_from_id(211).unwrap();
        assert_eq!(atomic_typedef_raw.get_kind(), BTF_KIND_TYPEDEF);
        assert_eq!(split.get_type_name(&atomic_typedef_raw), "atomic_t");

        let atomic_typedef = inner_to_btf_type(atomic_typedef_raw, 211).unwrap();
        assert_eq!(atomic_typedef.kind_specific_size(), 0);
    }

    #[test]
    fn test_vmlinux_btf_char() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        let char = split.raw_type_from_id(9).unwrap();
        assert_eq!(char.get_kind(), BTF_KIND_INT);
        assert_eq!(split.get_type_name(&char), "char");

        let char = inner_to_btf_type(char, 9).unwrap();
        assert_eq!(char.kind_specific_size(), 4);
    }

    #[test]
    fn test_vmlinux_do_brk_flags() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
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
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        let btf_type = split.type_from_id(23).unwrap();
        let (prefix, _suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct kernel_param");

        let type_id = split.structs["kernel_param"];
        assert_eq!(type_id, 23);
    }

    #[test]
    fn test_vmlinux_pointers() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let btf_type = split.type_from_id(5).unwrap();
        let (prefix, _suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "void *");

        let btf_type = split.type_from_id(111).unwrap();
        let (prefix, _suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct posix_acl *");

        let btf_type = split.type_from_id(120).unwrap();
        let (prefix, _suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "const struct inode_operations *");

        let btf_type = split.type_from_id(1801).unwrap();
        let (prefix, _suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "const struct mm_struct *const");

        let btf_type = split.type_from_id(1804).unwrap();
        let (prefix, _suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct file *const");
    }

    #[test]
    fn test_vmlinux_array() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let btf_type = split.type_from_id(336).unwrap();
        let (prefix, suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct percpu_counter");
        assert_eq!(suffix, "[4]");

        let btf_type = split.type_from_id(335).unwrap();
        let (prefix, suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "unsigned long");
        assert_eq!(suffix, "[50]");

        // TODO test array[N][M]
    }

    #[test]
    fn test_vmlinux_func_proto() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let btf_type = split.type_from_id(28257).unwrap();
        let (prefix, suffix) = btf_type.string_format(&split);
        assert_eq!(prefix, "struct mm_struct *");
        assert_eq!(suffix, "(struct task_struct * task, unsigned int mode)");
    }

    #[test]
    fn test_vmlinux_func_parameters() {
        let split = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        let func = split.find_function("vfs_open").unwrap();
        let btf_type = split.type_from_id(func.type_id).unwrap();

        match btf_type {
            BtfType::Func(func) => {
                let func_name = split.get_type_name(&func.btf_raw_type);
                assert_eq!(func_name, "vfs_open");

                let params = func.parameters(&split);
                assert_eq!(params.len(), 2);

                assert_eq!(params[0].name, "path");
                assert_eq!(params[0].type_id, 1920);
                let btf_type = split.type_from_id(params[0].type_id).unwrap();
                let (prefix, _suffix) = btf_type.string_format(&split);
                assert_eq!("const struct path *", prefix);

                assert_eq!(params[1].name, "file");
                assert_eq!(params[1].type_id, 216);
                let btf_type = split.type_from_id(params[1].type_id).unwrap();
                let (prefix, _suffix) = btf_type.string_format(&split);
                assert_eq!("struct file *", prefix);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_resolve_alloc_pid() {
        let btf = btf_module_get("vmlinux").unwrap();

        let f = btf_resolve_func(&btf, "alloc_pid").unwrap();
        assert_eq!(f.name, "alloc_pid");
        // TODO spaces after "*"
        assert_eq!(
            f.full_name,
            "struct pid * alloc_pid(struct pid_namespace * ns, pid_t * set_tid, size_t set_tid_size)"
        );
        assert_eq!(f.args.len(), 3);
        assert_eq!(f.args[0].name, "ns");
        assert_eq!(f.args[1].name, "set_tid");
        assert_eq!(f.args[2].name, "set_tid_size");

        let var_name = btf_variable_name(&btf, &f.args[0]).unwrap();
        assert_eq!(var_name.type_name, "struct pid_namespace *");
        assert_eq!(var_name.full_name, "struct pid_namespace *ns");

        let var_name = btf_variable_name(&btf, &f.args[1]).unwrap();
        assert_eq!(var_name.type_name, "pid_t *");
        assert_eq!(var_name.full_name, "pid_t *set_tid");

        let var_name = btf_variable_name(&btf, &f.args[2]).unwrap();
        assert_eq!(var_name.type_name, "size_t");
        assert_eq!(var_name.full_name, "size_t set_tid_size");
    }

    #[test]
    fn test_resolve_struct_inode_ptr() {
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let inode_ptr = btf_resolve_type(&btf, 6292).unwrap();
        assert_eq!(inode_ptr.type_prefix, "const struct inode *");
        assert_eq!(inode_ptr.actual_type_id, 110);

        let inode_struct = inode_ptr.actual_type.unwrap();
        assert_eq!(inode_struct.type_name, "struct inode");
        assert_eq!(btf.structs["inode"], 110);

        assert_eq!(inode_struct.members[0].name, "i_mode");
        assert_eq!(inode_struct.members[10].name, "i_ino");
        assert_eq!(inode_struct.members[20].name, "i_generation");

        assert_eq!(inode_struct.members.len(), 47);
    }

    #[test]
    fn test_resolve_rcu_special_union() {
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let union = btf_resolve_type(&btf, 430).unwrap();
        assert_eq!(union.type_prefix, "union rcu_special");
        assert_eq!(union.actual_type_id, 430);

        let union = union.actual_type.unwrap();
        assert_eq!(union.type_name, "union rcu_special");

        assert_eq!(union.members[0].name, "b");
        assert_eq!(union.members[1].name, "s");

        assert_eq!(union.members.len(), 2);
    }

    #[test]
    fn test_resolve_alloc_worqueue_noprof() {
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        let base = btf_resolve_func(&btf, "alloc_workqueue_noprof").unwrap();

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "retval").unwrap();

        assert_eq!(resolved_var.name, "retval");
        assert_eq!(resolved_type.type_prefix, "struct workqueue_struct *");

        assert!(resolved_type
            .actual_type
            .as_ref()
            .unwrap()
            .members
            .iter()
            .any(|v| v.name == "mutex"));

        assert!(resolved_type
            .actual_type
            .as_ref()
            .unwrap()
            .members
            .iter()
            .any(|child| child.name == "pwqs"));
    }

    #[test]
    fn test_iterate_over_mixed_chain() {
        // alloc_pid: ns->rcu.next->func
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let base = btf_resolve_func(&btf, "alloc_pid").unwrap();

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.ns->rcu.next").unwrap();
        assert!(resolved_var.name == "next");
        assert!(resolved_type.actual_type.unwrap().members[0].name == "next");

        let (resolved_var, _resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.ns->rcu.func").unwrap();
        assert_eq!(resolved_var.name, "func");
        // TODO
        // assert_eq!(resolved_type.type_prefix, "void *");
        // assert_eq!(
        //     resolved_type.type_suffix,
        //     "void (*)( struct callback_head * )"
        // );

        let resolved_fail = btf_iterate_function_args(&btf, &base, "args.ns->rcu->next");
        assert!(resolved_fail.is_none());
    }

    #[test]
    fn test_resolve_k_itimer_union() {
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let base = btf_resolve_func(&btf, "posixtimer_send_sigqueue").unwrap();
        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.tmr->it").unwrap();

        assert_eq!(resolved_var.name, "it");
        assert_eq!(resolved_type.type_prefix, "union ");
        assert_eq!(resolved_type.type_suffix, "");

        let actual_type = resolved_type.actual_type.unwrap();
        let cpu_member = actual_type
            .members
            .iter()
            .find(|&r| r.name == "cpu")
            .unwrap();

        assert_eq!(cpu_member.name, "cpu");

        let cpu_timer_type = btf_resolve_type(&btf, cpu_member.type_id).unwrap();
        assert_eq!(cpu_timer_type.type_prefix, "struct cpu_timer");
    }

    #[test]
    fn test_resolve_vfs_open() {
        // vfs_open: path->dentry->d_inode->i_uid
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();

        let base = btf_resolve_func(&btf, "vfs_open").unwrap();
        assert!(base.name == "vfs_open");

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.").unwrap();
        assert_eq!(resolved_var.name, "vfs_open");

        let members = resolved_type.actual_type.unwrap().members;
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "path");
        assert_eq!(members[1].name, "file");

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "retval").unwrap();
        assert_eq!(resolved_var.name, "retval");
        assert_eq!(resolved_type.type_prefix, "int");
        assert!(resolved_type.actual_type.is_none());

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.path").unwrap();
        assert_eq!(resolved_var.name, "path");
        assert_eq!(resolved_type.type_prefix, "const struct path *");
        let actual_type = resolved_type.actual_type.unwrap();
        assert_eq!(actual_type.type_name, "struct path");
        assert_eq!(actual_type.members[0].name, "mnt");

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.path->dentry->d_inode").unwrap();
        assert_eq!(resolved_var.name, "d_inode");
        assert_eq!(resolved_type.type_prefix, "struct inode *");
        let actual_type = resolved_type.actual_type.unwrap();
        assert_eq!(actual_type.type_name, "struct inode");
        assert_eq!(actual_type.members[0].name, "i_mode");

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.path.dentry").unwrap();
        assert_eq!(resolved_var.name, "dentry");
        assert_eq!(resolved_type.type_prefix, "struct dentry *");
        let actual_type = resolved_type.actual_type.unwrap();
        assert_eq!(actual_type.type_name, "struct dentry");
        assert_eq!(actual_type.members[0].name, "d_flags");
    }

    #[test]
    fn test_resolve_fuse() {
        let btf = btf_module_get("fuse").unwrap();

        let base = btf_resolve_func(&btf, "fuse_dentry_delete").unwrap();
        assert!(base.name == "fuse_dentry_delete");

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "retval").unwrap();
        assert_eq!(resolved_var.name, "retval");
        assert_eq!(resolved_type.type_prefix, "int");

        assert!(resolved_type.actual_type.is_none());
        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.dentry").unwrap();
        assert_eq!(resolved_var.name, "dentry");
        assert_eq!(resolved_type.type_prefix, "const struct dentry *");

        let (resolved_var, resolved_type) =
            btf_iterate_function_args(&btf, &base, "args.dentry->d_flags").unwrap();
        assert_eq!(resolved_var.name, "d_flags");
        assert_eq!(resolved_type.type_prefix, "unsigned int");
    }

    #[test]
    fn test_resolve_inode_struct() {
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        let resolved_type = btf_resolve_struct(&btf, "inode").unwrap();

        let actual_type = resolved_type.actual_type.unwrap();
        assert_eq!(actual_type.type_name, "struct inode");
        assert_eq!(actual_type.members[0].name, "i_mode");

        let (res_var, res_type) =
            btf_iterate_members(&btf, "INODE", &actual_type, "args.INODE->i_sb->s_bdi").unwrap();
        assert_eq!(res_var.name, "s_bdi");
        assert_eq!(res_type.type_prefix, "struct backing_dev_info *");
    }

    #[test]
    fn test_resolve_btf_iter_link_info_union() {
        let btf = BtfSplit::build(None, VMLINUX_BTF_PATH).unwrap();
        let resolved_type = btf_resolve_union(&btf, "bpf_iter_link_info").unwrap();

        let actual_type = resolved_type.actual_type.unwrap();
        assert_eq!(actual_type.type_name, "union bpf_iter_link_info");
        assert_eq!(actual_type.members[0].name, "map");
        assert_eq!(actual_type.members[0].type_id, 7835);
        assert_eq!(actual_type.members[1].name, "cgroup");
        assert_eq!(actual_type.members[1].type_id, 7836);
        assert_eq!(actual_type.members[2].name, "task");
        assert_eq!(actual_type.members[2].type_id, 7837);

        let (res_var, res_type) =
            btf_iterate_members(&btf, "iter", &actual_type, "args.iter->task.tid").unwrap();
        assert_eq!(res_var.name, "tid");
        assert_eq!(res_type.type_prefix, "__u32");
    }
}
