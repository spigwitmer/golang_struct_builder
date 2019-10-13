"""
golang_struct_builder.py

An IDA 7.0+ script for Go binaries that automatically renames
and creates structures from detected go types found in runtime
module data.

Must run golang_loader_assist beforehand for it to be useful,
which can be found at https://github.com/strazzere/golang_loader_assist
(IDA 7.0 compatible fork: https://github.com/spigwitmer/golang_loader_assist)
"""
__author__ = "spigwitmer"
__license__ = "GPL"
__version__ = "0.1"

from idautils import *
from idc import *
import idaapi
import ida_enum
import ida_nalt
import ida_segment
import ida_typeinf
from ida_funcs import get_func
from ida_name import get_name_ea, get_name, set_name, \
        SN_PUBLIC, is_in_nlist
from ida_ua import get_dtype_size
from ida_bytes import get_byte, STRCONV_ESCAPE
from idaapi import offflag, enum_flag
import sys
import string
import logging

DEBUG = False

logging.basicConfig(
        level=logging.DEBUG if DEBUG else logging.INFO
        )

LOG = logging.getLogger('golang_struct_builder')

# this makes the assumption you've ran
# golang_loader_assist beforehand

# other assumptions being made currently:
# - x86_64 arch
# - go1.11

PTRSIZE = 8
INTSIZE = 8
FF_INT = (FF_QWORD if INTSIZE == 8 else FF_DWORD)
FF_PTR = (FF_QWORD if PTRSIZE == 8 else FF_DWORD)

# opinfo for offsets of the current segment
OFF_CURRENT_SEGMENT = idaapi.opinfo_t()
OFF_CURRENT_SEGMENT.ri.base = BADADDR
OFF_CURRENT_SEGMENT.ri.target = BADADDR
OFF_CURRENT_SEGMENT.ri.flags = ida_nalt.REF_OFF64

GO_BUILTIN_STRUCTS = [
    # primitives
    ('go_string', [
        # (name, size(int) or struct name(str), typeflags, opinfo, enum,
        #  offset (or None placing at the end of the struct))
        ('str', PTRSIZE, FF_QWORD|FF_DATA|offflag(),
                OFF_CURRENT_SEGMENT, None, None),
        ('len', INTSIZE, FF_QWORD|FF_DATA, None, None, None)
        ]),
    ('go_array', [
        ('data', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('len', INTSIZE, FF_QWORD|FF_DATA, None, None, None),
        ('cap', INTSIZE, FF_QWORD|FF_DATA, None, None, None)
        ]),
    ('go_slice', [
        ('array', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('len', INTSIZE, FF_INT|FF_DATA, None, None, None),
        ('cap', INTSIZE, FF_INT|FF_DATA, None, None, None)
        ]),
    ('go_complex64', [
        ('real', 4, FF_FLOAT|FF_DATA, None, None, None),
        ('imag', 4, FF_FLOAT|FF_DATA, None, None, None)
        ]),
    ('go_complex128', [
        ('real', 8, FF_DOUBLE|FF_DATA, None, None, None),
        ('imag', 8, FF_DOUBLE|FF_DATA, None, None, None)
        ]),
    ('go_hmap', [
        ('count', 8, FF_QWORD|FF_DATA, None, None, None),
        ('flags', 1, FF_BYTE|FF_DATA, None, 'go_maptype_flags', None),
        ('B', 1, FF_BYTE|FF_DATA, None, None, None),
        ('noverflow', 2, FF_WORD|FF_DATA, None, None, None),
        ('hash0', 4, FF_DWORD|FF_DATA, None, None, None),
        ('buckets', PTRSIZE, FF_QWORD|FF_DATA, OFF_CURRENT_SEGMENT,
            None, None),
        ('oldbuckets', PTRSIZE, FF_QWORD|FF_DATA, OFF_CURRENT_SEGMENT,
            None, None),
        ('nevacuate', 8, FF_QWORD|FF_DATA, None, None, None),
        # TODO: mapextra struct
        ('extra', PTRSIZE, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None)
        ]),
    ('go_waitq', [
        ('first', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('last', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None)
        ]),

    # TODO: this is a placeholder. Find out what actually consists
    # of an interface when embedded in a struct
    ('go_interface', [ 
        ('placeholder0', 8, FF_QWORD|FF_DATA, None, None, None),
        ('placeholder1', 8, FF_QWORD|FF_DATA, None, None, None)
        ]),
    ('go_mutex', [
        ('key', PTRSIZE, FF_PTR|FF_DATA, None, None, None)
        ]),
    ('go_hchan', [
        ('qcount', INTSIZE, FF_INT|FF_DATA, None, None, None),
        ('dataqsiz', INTSIZE, FF_INT|FF_DATA, None, None, None),
        ('buf', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('elemsize', 2, FF_WORD|FF_DATA, None, None, None),
        ('closed', 4, FF_DWORD|FF_DATA, None, None, None),
        ('elemtype', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('sendx', INTSIZE, FF_INT|FF_DATA, None, None, None),
        ('recvx', INTSIZE, FF_INT|FF_DATA, None, None, None),
        ('recvq', 'go_waitq', None, None, None, None),
        ('sendq', 'go_waitq', None, None, None, None),
        ('lock', 'go_mutex', None, None, None, None)
        ]),
    ('go_name', [
        ('flags', 1, FF_BYTE|FF_DATA, None, 'go_NameFlags', None),
        ('length_hi', 1, FF_BYTE|FF_DATA, None, None, None),
        ('length_lo', 1, FF_BYTE|FF_DATA, None, None, None),
        ('str', 0, FF_DATA|FF_STRLIT, idaapi.opinfo_t(), None, None)
        ]),
    ('go_tag', [
        ('length_hi', 1, FF_BYTE|FF_DATA, None, None, None),
        ('length_lo', 1, FF_BYTE|FF_DATA, None, None, None),
        ('str', 0, FF_DATA|FF_STRLIT, idaapi.opinfo_t(), None, None)
        ]),
    ('go_runtime_bitvector', [
        ('n', 4, FF_DWORD|FF_DATA, None, None, None),
        ('bytedata', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None)
        ]),

    # go_type metadata structs
    #
    # these are technically supposed to be represented
    # as different types of go_type, however the decision
    # was made to represent them as a separate struct that
    # follows a go_type instead
    ('go_type_metadata_chan', [
        ('elem', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('dir', PTRSIZE, FF_PTR|FF_DATA, None, None, None)
        ]),
    ('go_type_metadata_map', [
        ('key', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('elem', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('bucket', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('keysize', 1, FF_BYTE|FF_DATA, None, None, None),
        ('elemsize', 1, FF_BYTE|FF_DATA, None, None, None),
        ('bucketsize', 2, FF_WORD|FF_DATA, None, None, None),
        ('flags', 4, FF_DWORD|FF_DATA, None, 'go_maptype_flags', None)
        ]),
    ('go_type_metadata_iface', [
        ('pkgPath', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('mhdr', 'go_slice', None, None, None, None)
        ]),
    ('go_type_metadata_ptr', [
        ('_elem', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None)
        ]),
    ('go_type_metadata_func', [
        ('inCount', 2, FF_WORD|FF_DATA, None, None, None),
        ('outCount', 2, FF_WORD|FF_DATA, None, None, None)
        ]),
    ('go_type_metadata_array', [
        ('elem', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('slice', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('len', PTRSIZE, FF_PTR|FF_DATA, None, None, None)
        ]),
    ('go_type_metadata_slice', [
        ('elem', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None)
        ]),
    # go_type_structfield is pointed to by go_type_metadata_struct
    # as `fields`
    ('go_type_structfield', [
        ('name', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('typ', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('offsetAnon', PTRSIZE, FF_INT|FF_DATA, None, None, None)
        ]),
    ('go_type_metadata_struct', [
        ('pkgPath', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('fields', 'go_slice', None, None, None, None)
        ]),

    ('go_itab', [
        ('inter', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('_type', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('hash', 4, FF_DWORD, None, None, None),
        ('_', 4, FF_DWORD|FF_DATA, None, None, None),
        ('fun', 0, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None)
        ]),
    ('go_runtime_moduledata', [
        ('pclntable', 'go_slice', None, None, None, None),
        ('ftab', 'go_slice', None, None, None, None),
        ('filetab', 'go_slice', None, None, None, None),
        ('findfunctab', 8, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('minpc', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('maxpc', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('text', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('etext', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('noptrdata', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('enoptrdata', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('data', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('edata', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('bss', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('ebss', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('noptrbss', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('enoptrbss', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('end', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('gcdata', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('gcbss', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('types', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('etypes', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('textsecmap', 'go_slice', None, None, None, None),
        ('typelinks', 'go_slice', None, None, None, None),
        ('itablinks', 'go_slice', None, None, None, None),
        ('ptab', 'go_slice', None, None, None, None),
        ('pluginpath', 'go_string', None, None, None, None),
        ('pkgHashes', 'go_slice', None, None, None, None),
        ('modulename', 'go_string', None, None, None, None),
        ('modulehashes', 'go_slice', None, None, None, None),
        ('hasmain', 1, FF_BYTE|FF_DATA, None, None, None),
        ('gcdatamask', 'go_runtime_bitvector', None, None, None, None),
        ('gcbssmask', 'go_runtime_bitvector', None, None, None, None),
        ('typemap', 'go_hmap', None, None, None, None),
        ('bad', 1, FF_BYTE|FF_DATA, None, None, None),
        ('next', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None)
        ])
    ]


# list of typedata offset ranges (as a tuple) from
# each moduledata entry in the order that they're found
GO_TYPES_RANGES = list()


def create_and_populate_struct(struct_name, struct_fields,
                               member_comments=None,
                               member_tinfos=None):
    """
    Creates a new IDA structure

    :param struct_name: structure name
    :param struct_fields: tuple of field information
                          (see beginning of GO_BUILTIN_STRUCTS)
    :param member_comments: list of comments for each member.
                            length must be equal to struct_fields
    :param member_tinfos: list of tinfo_t descriptors for each member.
                          length must be equal to struct_fields
    :return: struct_t of the newly created struct
    """
    if member_comments:
        if len(member_comments) != len(struct_fields):
            LOG.error(
                'len(member_comments) != len(struct_fields).' \
                       ' %d is not %d.',
                len(member_comments), len(struct_fields)
                )

    if member_tinfos:
        if len(member_tinfos) != len(struct_fields):
            LOG.error(
                'len(member_tinfos) != len(struct_fields).' \
                       ' %d is not %d.' % \
                len(member_tinfos), len(struct_fields)
                )

    existing_struct = ida_struct.get_struc_id(struct_name)
    if existing_struct != BADADDR:
        LOG.info('struct %s already exists, skipping..',
                 struct_name)
        return

    new_struct = ida_struct.add_struc(BADADDR, struct_name)
    new_sptr = ida_struct.get_struc(new_struct)
    idx = 0
    for name, struct_name_or_size, typeflags, opinfo, enum_ptr, \
            member_offset in struct_fields:
        if member_offset is None:
            member_offset = BADADDR
        LOG.debug('adding struct field %s:%s:%s',
                  struct_name, name, member_offset)
        if type(struct_name_or_size) in (str,unicode):
            # plaster in an existing struct
            existing_struct_field = ida_struct.get_struc_id(
                                        struct_name_or_size)
            if existing_struct_field == BADADDR:
                LOG.error('trying to add struct type %s ' \
                          'as field before it is declared, ' \
                          'cannot continue',
                          struct_name_or_size)
                break
            existing_sptr = ida_struct.get_struc(existing_struct_field)
            existing_size = ida_struct.get_struc_size(existing_sptr)
            opinfo = idaapi.opinfo_t()
            opinfo.tid = existing_struct_field
            ida_struct.add_struc_member(new_sptr,
                                        name,
                                        member_offset,
                                        FF_STRUCT|FF_DATA,
                                        opinfo,
                                        existing_size)
        else:
            if enum_ptr:
                existing_enum = ida_enum.get_enum(enum_ptr)
                LOG.debug('existing_enum: %x', existing_enum)
                if existing_enum == BADADDR:
                    LOG.error('enum %s does not exist, ' \
                              'cannot continue', enum_ptr)
                    break
                opinfo = idaapi.opinfo_t()
                opinfo.ec.tid = existing_enum
                opinfo.ec.serial = ida_enum.get_enum_idx(
                                        existing_enum)
                typeflags |= FF_0ENUM
            ida_struct.add_struc_member(
                    new_sptr, name, member_offset,
                    typeflags, opinfo,
                    struct_name_or_size)
        if member_comments and member_comments[idx]:
            new_member_mptr = ida_struct.get_member_by_name(
                                     new_sptr, name)
            ida_struct.set_member_cmt(new_member_mptr,
                                      member_comments[idx],
                                      False)
        if member_tinfos and member_tinfos[idx]:
            new_member_mptr = ida_struct.get_member_by_name(
                                     new_sptr, name)
            ida_struct.set_member_tinfo(new_sptr,
                                        new_member_mptr,
                                        0,
                                        member_tinfos[idx],
                                        0)
        idx += 1
    return new_sptr


NAME_FLAGS = {
    'exported': 1,
    'tagFollowsName': 2,
    'pkgPathFollowsTag': 4
    }

TYPE_TFLAGS = {
    'uncommon': 1,
    'extraStar': 2,
    'named': 4
    }

TYPEKIND_VALS = {
    # kind: (enum value, mask)
    'kindBool': (1, 0x1f),
    'kindInt': (2, 0x1f),
    'kindInt8': (3, 0x1f),
    'kindInt16': (4, 0x1f),
    'kindInt32': (5, 0x1f),
    'kindInt64': (6, 0x1f),
    'kindUint': (7, 0x1f),
    'kindUint8': (8, 0x1f),
    'kindUint16': (9, 0x1f),
    'kindUint32': (10, 0x1f),
    'kindUint64': (11, 0x1f),
    'kindUintptr': (12, 0x1f),
    'kindFloat32': (13, 0x1f),
    'kindFloat64': (14, 0x1f),
    'kindComplex64': (15, 0x1f),
    'kindComplex128': (16, 0x1f),
    'kindArray': (17, 0x1f),
    'kindChan': (18, 0x1f),
    'kindFunc': (19, 0x1f),
    'kindInterface': (20, 0x1f),
    'kindMap': (21, 0x1f),
    'kindPtr': (22, 0x1f),
    'kindSlice': (23, 0x1f),
    'kindString': (24, 0x1f),
    'kindStruct': (25, 0x1f),
    'kindUnsafePointer': (26, 0x1f),
    'kindDirectIface': (0x20, 0x20),
    'kindGCProg': (0x40, 0x40),
    'kindNoPointers': (0x80, 0x80)
    }

TYPEKIND_SIZES = {
    TYPEKIND_VALS['kindBool'][0]: 1,
    TYPEKIND_VALS['kindInt'][0]: INTSIZE,
    TYPEKIND_VALS['kindInt8'][0]: 1,
    TYPEKIND_VALS['kindInt16'][0]: 2,
    TYPEKIND_VALS['kindInt32'][0]: 4,
    TYPEKIND_VALS['kindInt64'][0]: 8,
    TYPEKIND_VALS['kindUint'][0]: INTSIZE,
    TYPEKIND_VALS['kindUint8'][0]: 1,
    TYPEKIND_VALS['kindUint16'][0]: 2,
    TYPEKIND_VALS['kindUint32'][0]: 4,
    TYPEKIND_VALS['kindUint64'][0]: 8,
    TYPEKIND_VALS['kindUintptr'][0]: 8,
    TYPEKIND_VALS['kindFloat32'][0]: 4,
    TYPEKIND_VALS['kindFloat64'][0]: 8,
    TYPEKIND_VALS['kindComplex64'][0]: 8,
    TYPEKIND_VALS['kindComplex128'][0]: 16,
    # sizeof(go_array)
    TYPEKIND_VALS['kindArray'][0]: 16+PTRSIZE,
    # sizeof(go_hchan)
    TYPEKIND_VALS['kindChan'][0]: 6+(INTSIZE*4)+(PTRSIZE*4),
    TYPEKIND_VALS['kindFunc'][0]: PTRSIZE,
    TYPEKIND_VALS['kindInterface'][0]: 16,
    # sizeof(go_hmap)
    TYPEKIND_VALS['kindMap'][0]: 24+(PTRSIZE*3),
    TYPEKIND_VALS['kindPtr'][0]: PTRSIZE,
    TYPEKIND_VALS['kindSlice'][0]: PTRSIZE,
    # sizeof(go_string)
    TYPEKIND_VALS['kindString'][0]: PTRSIZE+8,
    TYPEKIND_VALS['kindUnsafePointer'][0]: PTRSIZE,
    }

GO_BUILTIN_BITFIELDS = {
    # bitfield_name: (width, values)
    'go_tflag': (1, { # type flags
        # value_name: (value, mask)
        'tflagUncommon': (TYPE_TFLAGS['uncommon'], 0x01),
        'tflagExtraStar': (TYPE_TFLAGS['extraStar'], 0x02),
        'tflagNamed': (TYPE_TFLAGS['named'], 0x04)
        }),
    'go_NameFlags': (1, { # name flags
        'nameExported': (NAME_FLAGS['exported'], 0x1),
        'nameTagFollowsName': (NAME_FLAGS['tagFollowsName'], 0x2),
        'namePkgPathFollowsTag': (NAME_FLAGS['pkgPathFollowsTag'], 0x4),
        }),
    'go_typekind': (1, TYPEKIND_VALS),
    'go_maptype_flags': (1, {
        'IndirectKey': (1, 0x1),
        'IndirectElem': (2, 0x2),
        'ReflexiveKey': (4, 0x4),
        'NeedKeyUpdate': (8, 0x8),
        'HashMightPanic': (16, 0x10)
        })
    }


def populate_builtin_bitfields():
    """
    Creates enums out of useful builtin bitfields from
    Go's runtime module.
    """
    for bf_name, (bf_size, bf_values) in GO_BUILTIN_BITFIELDS.items():
        existing_enum = ida_enum.get_enum(bf_name)
        if existing_enum != BADADDR:
            LOG.info('bitfield %s already exists, skipping..',
                     bf_name)
            continue
        new_bf_id = ida_enum.add_enum(BADADDR, bf_name, 0)
        ida_enum.set_enum_bf(new_bf_id, True)
        ida_enum.set_enum_width(new_bf_id, bf_size)
        for name, (enum_val, bf_mask) in bf_values.items():
            ret = ida_enum.add_enum_member(new_bf_id, name,
                                           enum_val, bf_mask)
            if ret != 0:
                LOG.error('Could not add %s bitfield value to %s ' \
                          '(error code %d)', name, bf_name, ret)
                break


def get_struct_val(ea, fullname):
    """
    Get member value described by `fullname` from structure
    starting at `ea`

    :param ea: effective address of structure start
    :param fullname: member name in the form of "structname.membername"
    """
    struct_member = ida_struct.get_member_by_fullname(fullname)[0]
    member_type_flag = struct_member.flag & ida_bytes.DT_TYPE
    type_ret_map = {
        ida_bytes.FF_BYTE: ida_bytes.get_byte,
        ida_bytes.FF_WORD: ida_bytes.get_word,
        ida_bytes.FF_DWORD: ida_bytes.get_dword,
        ida_bytes.FF_QWORD: ida_bytes.get_qword
        }
    if member_type_flag not in type_ret_map.keys():
        # TODO: arrays and child structs
        raise NotImplementedError(
                'get_struct_val(%x)' % member_type_flag)
    return type_ret_map[member_type_flag](ea + struct_member.soff)



NAME_RE = re.compile(r'^(\[(?P<arrlen>[0-9]*)])?(?P<remain>.*)')
NON_ALNUM = re.compile('[^a-zA-Z0-9]')

def normalize_name(name, ea, prepend_type_info=True):
    """
    Sanitizes name for a given go type

    :param name: name to sanitize
    :param ea: effective address of go type start
    :param prepend_type_info: prefix sanitized name with info about
                              the type itself.
    """
    normalized_name = []
    if prepend_type_info:
        if ea in [0, BADADDR]:
            raise Exception('normalize_name: EA required ' \
                                'for type prepend')
        prefixes = {
            TYPEKIND_VALS['kindPtr'][0]: 'ptr_',
            TYPEKIND_VALS['kindArray'][0]: 'arr_',
            TYPEKIND_VALS['kindSlice'][0]: 'slc_',
            TYPEKIND_VALS['kindFunc'][0]: 'func_',
            TYPEKIND_VALS['kindChan'][0]: 'chan_',
            TYPEKIND_VALS['kindMap'][0]: 'map_',
            TYPEKIND_VALS['kindStruct'][0]: 'stct_',
            TYPEKIND_VALS['kindInterface'][0]: 'iface_'
            }
        tkind = (get_struct_val(ea, 'go_type0.kind') & 0x1f)
        if tkind in prefixes.keys():
            normalized_name.append(prefixes[tkind])
    name_match = NAME_RE.match(name)
    if name_match:
        matches = name_match.groupdict()
        if matches['arrlen']:
            normalized_name.append(matches['arrlen'])
        normalized_name.append(NON_ALNUM.sub('_', matches['remain']))
    else:
        # idk?
        normalized_name.append(NON_ALNUM.sub('_', name))
    return '_'.join(normalized_name)


def get_segment_offsets(segm_name):
    """
    Return start and end of segment with the given name

    :param segm_name: segment name
    :return: tuple (start, end)
    """
    segm = idaapi.get_segm_by_name(segm_name)
    if not segm:
        if segm_name.startswith('.'):
            # Mach-O binaries...
            segm = idaapi.get_segm_by_name('__' + segm_name[1:])
        if not segm:
            raise Exception('could not find %s segment' % segm_name)
    return segm.start_ea, segm.end_ea


def resolve_name(name):
    """
    returns the address of the given symbol `name`. Will search for
    mangled variation of `name` as a fallback (seen in Mach-O binaries).
    """
    origret = get_name_ea(BADADDR, name)
    if origret == BADADDR:
        return get_name_ea(BADADDR, name.replace('.', '_', 1))
    return origret


def map_type_structs():
    """
    Scan and recursively declare go types, creating new names where
    needed.
    """

    rodata_start_ea, _ = get_segment_offsets('.rodata')
    typelink_start_ea, typelink_end_ea = get_segment_offsets('.typelink')
    num_types = (typelink_end_ea - typelink_start_ea) / 4
    types_parsed = 0
    structs_created = 0
    for idx in range(0, num_types):
        type_ea = rodata_start_ea + \
                ida_bytes.get_dword(typelink_start_ea + (idx*4))
        if not ida_bytes.is_struct(ida_bytes.get_flags(type_ea)):
            LOG.debug('parsing go_type data at %x', type_ea)
            type_struct = declare_and_parse_go_type(type_ea)
            if type_struct != None:
                # give it a unique name
                success, type_name, type_tag, type_pkgdata = \
                        create_name(type_ea, type_struct)
                if success and not is_in_nlist(type_ea):
                    LOG.debug('created go_name for %s', type_name)
                    normalized_name = normalize_name(type_name, type_ea)
                    set_name(type_ea, 'go_type__' + normalized_name)
                    types_parsed += 1

                # create new IDA structure out of the struct reflect
                # data
                typekind = (get_struct_val(type_ea, 'go_type0.kind') & 0x1f)
                if typekind == TYPEKIND_VALS['kindStruct'][0]:
                    create_go_struct(type_ea)
                    structs_created += 1
                elif typekind == TYPEKIND_VALS['kindInterface'][0]:
                    LOG.info('go_interface found at 0x%x', type_ea)


    runtime_newobject_fn = resolve_name('runtime.newobject')
    if runtime_newobject_fn == BADADDR:
        LOG.error('Could not find runtime.newobject, not moving on ' \
                  '(did you run golang_loader_assist.py beforehand?)')
        return types_parsed, structs_created

    for fn_name in ['runtime.newobject', 'runtime.convT2Enoptr',
                    'runtime.convT2Eslice', 'runtime.convT2E',
                    'runtime.convT2E16', 'runtime.convT2E32',
                    'runtime.convT2E64', 'runtime.convT2Estring']:
        fn_ea = resolve_name(fn_name)
        if fn_ea == BADADDR:
            LOG.warn('could not find function %s, skipping...',
                     fn_name)
            continue

        LOG.info('parsing go_type structs from references to %s',
                 fn_name)

        for newobject_xref in XrefsTo(fn_ea, 0):
            # find the most recent mov to [rsp] prior to the call
            # instruction, continue backtracking til you find
            # the register being assigned an EA to an immediate value
            #
            # lea rbx, unk_XXXXXX
            # ...
            # mov [rsp], rbx
            # ...
            # call runtime_newobject
            register_n = -1
            xref_func = get_func(newobject_xref.frm)
            go_type_addr = BADADDR
            if not xref_func or xref_func.start_ea == BADADDR:
                continue

            inst = DecodePreviousInstruction(newobject_xref.frm)
            while inst and inst.ea != BADADDR:
                if inst.ea < xref_func.start_ea:
                    # we went past the actual function
                    LOG.debug('inst went past the function EA, wat..')
                    break

                if register_n == -1:
                    # is it the mov [rsp], xxx instruction?
                    if inst.Op1.specflag1: # SIB byte in effect
                        regsize = get_dtype_size(inst.Op1.dtype)
                        base_reg_n = inst.Op1.specflag2 & 7
                        if idaapi.get_reg_name(base_reg_n, regsize) == 'rsp' \
                                and inst.Op1.addr == 0:
                            register_n = inst.Op2.reg

                else:
                    # is it the lea xxx, unk_XXXXXX instruction?
                    if inst.Op1.reg == register_n and \
                            get_byte(inst.ea+1) == 0x8D:

                        # assure second operand is an immediate value
                        if inst.Op2.type == 2:
                            go_type_addr = inst.Op2.addr
                        else:
                            # it's grabbing it from a struct field
                            # or something. ignore it.  we're most
                            # likely in the "runtime" module anyway.
                            pass

                        break
                inst = DecodePreviousInstruction(inst.ea)

            if go_type_addr != BADADDR and not ida_bytes.is_struct(
                                    ida_bytes.get_flags(go_type_addr)):
                data_name = get_name(go_type_addr)
                LOG.debug('found go reflect data type at %s', data_name)
                type_struct = declare_and_parse_go_type(go_type_addr)
                if type_struct != None:
                    # give it a unique name
                    success, type_name, type_tag, type_pkgdata = \
                            create_name(go_type_addr, type_struct)
                    if success and not is_in_nlist(go_type_addr):
                        LOG.debug('created go_name for %s', type_name)
                        normalized_name = normalize_name(type_name, go_type_addr)
                        set_name(go_type_addr, 'go_type__' + normalized_name)
                        types_parsed += 1

                    # create new IDA structure out of the struct reflect
                    # data
                    typekind = (get_struct_val(go_type_addr, 'go_type0.kind') & 0x1f)
                    if typekind == TYPEKIND_VALS['kindStruct'][0]:
                        create_go_struct(go_type_addr)
                        structs_created += 1
                    elif typekind == TYPEKIND_VALS['kindInterface'][0]:
                        LOG.info('go_interface found at 0x%x',
                                 go_type_addr)
                        declare_interface(go_type_addr)

    return types_parsed, structs_created


STRUCT_REGISTRY = {}

def create_go_struct(ea):
    """
    Create an IDA structure out of the given go_type
    at `ea`.

    :param ea: go_type effective address
    """
    tflags = get_struct_val(ea, 'go_type0.tflag')
    type_kind = (get_struct_val(ea, 'go_type0.kind') & 0x1f)
    if type_kind != TYPEKIND_VALS['kindStruct'][0]:
        raise Exception('go_type at 0x%x not a struct' % \
                ea)
    type_struct_size = ida_struct.get_struc_size(
            ida_struct.get_struc(ida_struct.get_struc_id('go_type0')))
    type_kind_ea = ea + type_struct_size
    fields_soff = ida_struct.get_member_by_fullname(
            'go_type_metadata_struct.fields')[0].soff

    struct_name = 'anonymous_struct_%x' % ea
    if tflags & TYPE_TFLAGS['named']:
        struct_name = normalize_name(get_type_name(ea), None,
                                     prepend_type_info=False)
        if tflags & TYPE_TFLAGS['extraStar']:
            struct_name = struct_name[1:]
        struct_name = 'go_struct__' + struct_name

    if ea in STRUCT_REGISTRY:
        LOG.debug('go struct at 0x%x already named', ea)
        return STRUCT_REGISTRY[ea]

    fields_ea = type_kind_ea + fields_soff
    num_fields = get_struct_val(fields_ea, 'go_array.len')
    new_struct_mptr = None
    LOG.debug('struct %s at 0x%x has %d fields',
              struct_name, fields_ea, num_fields)
    STRUCT_REGISTRY[ea] = (new_struct_mptr, struct_name)
    if num_fields > 0:
        fields_ptr_ea = get_struct_val(fields_ea,
                                       'go_array.data')
        LOG.debug('creating %d structfields at 0x%x',
                  num_fields, fields_ptr_ea)
        field_list, tag_list, tinfo_list = \
                create_structfields(fields_ptr_ea, num_fields)
        LOG.debug('0x%x: fields: %s', ea, field_list)
        new_struct_mptr = create_and_populate_struct(
                struct_name, field_list,
                member_comments=tag_list,
                member_tinfos=tinfo_list)
        if new_struct_mptr:
            STRUCT_REGISTRY[ea] = (new_struct_mptr, struct_name)
            ida_struct.set_struc_cmt(
                    new_struct_mptr.id,
                    '0x%x' % ea,
                    False)

    return (new_struct_mptr, struct_name)


def declare_and_parse_go_type(ea):
    """
    Declare type data and parse additional metadata based on the type
    (struct, interface, func, map, etc.)
    """
    # look at the offset for the str field
    type_idx = -1
    for idx, (md_soff, md_eoff) in enumerate(GO_TYPES_RANGES):
        if ea >= md_soff and ea < md_eoff:
            type_idx = idx
    if type_idx == -1:
        LOG.error('could not determine correct go_type struct ' \
                  'at 0x%x', ea)
        return None

    type_struct_name = 'go_type%d' % type_idx
    type_struct = ida_struct.get_struc(
            ida_struct.get_struc_id(type_struct_name))
    type_struct_size = ida_struct.get_struc_size(type_struct)

    tflag = get_struct_val(ea, 'go_type0.tflag')

    if not ida_bytes.del_items(ea, 0, type_struct_size):
        LOG.error('could not undefine bytes for go_type ' \
                  'at 0x%x', ea)
        return None

    if not ida_bytes.create_struct(ea, type_struct_size,
                                   type_struct.id):
        LOG.error('could not create go_type%d struct ' \
                  'at 0x%x', type_idx, ea)
        return None

    type_kind = (get_struct_val(ea, 'go_type0.kind') & 0x1f)
    type_kind_id = -1
    type_kind_size = 0
    type_kind_name = None

    # create metadata struct right after if it exists
    type_kind_ea = ea + type_struct_size
    if type_kind == TYPEKIND_VALS['kindFunc'][0]:
        type_kind_name = 'go_type_metadata_func'
    elif type_kind == TYPEKIND_VALS['kindMap'][0]:
        type_kind_name = 'go_type_metadata_map'
    elif type_kind == TYPEKIND_VALS['kindPtr'][0]:
        type_kind_name = 'go_type_metadata_ptr'
    elif type_kind == TYPEKIND_VALS['kindInterface'][0]:
        LOG.info('interface type at 0x%x', ea)
        type_kind_name = 'go_type_metadata_iface'
    elif type_kind == TYPEKIND_VALS['kindStruct'][0]:
        type_kind_name = 'go_type_metadata_struct'
    elif type_kind == TYPEKIND_VALS['kindArray'][0]:
        type_kind_name = 'go_type_metadata_array'
    elif type_kind == TYPEKIND_VALS['kindChan'][0]:
        type_kind_name = 'go_type_metadata_chan'
    elif type_kind == TYPEKIND_VALS['kindSlice'][0]:
        type_kind_name = 'go_type_metadata_slice'

    if type_kind_name:
        LOG.debug('adding %s at 0x%x', type_kind_name, type_kind_ea)
        type_kind_id = ida_struct.get_struc_id(type_kind_name)
        type_kind_sptr = ida_struct.get_struc(type_kind_id)
        type_kind_size = ida_struct.get_struc_size(type_kind_sptr)
        if type_kind_size <= 0:
            LOG.error('could not determine %s struct size ' \
                      'at 0x%x (%s)', type_kind_id, type_kind_ea)
            return type_struct
        LOG.debug('adding go_type struct metadata %s of %d bytes ' \
                  'at 0x%x',
                  type_kind_name, type_kind_size, type_kind_ea)
        ida_bytes.del_items(type_kind_ea, type_kind_size)
        if not ida_bytes.create_struct(type_kind_ea, type_kind_size,
                type_kind_id):
            LOG.error('could not declare typekind %s struct at ' \
                      '0x%x',
                      type_kind_name, type_kind_ea)

    if (tflag & TYPE_TFLAGS['uncommon']) != 0:
        uncommon_data_ea = type_kind_ea + type_kind_size
        uncommon_struct_name = 'go_type%d_metadata_uncommon' % \
                type_idx
        uncommon_struct_id = ida_struct.get_struc_id(
                                uncommon_struct_name)
        uncommon_sptr = ida_struct.get_struc(uncommon_struct_id)
        uncommon_struct_size = ida_struct.get_struc_size(uncommon_sptr)
        LOG.debug('Declaring uncommon type data at 0x%x',
                  uncommon_data_ea)
        ida_bytes.del_items(uncommon_data_ea, uncommon_struct_size)
        if not ida_bytes.create_struct(uncommon_data_ea,
                                       uncommon_struct_size,
                                       uncommon_struct_id):
            LOG.error('Could not declare uncommon type data at 0x%x',
                      uncommon_data_ea)

    return type_struct


## name metadata schtuff
## for more info, check out the logic starting at
## https://github.com/golang/go/blob/release-branch.go1.12/src/runtime/type.go#L439

def get_moduledata_name_offset(ea, name_offset):
    """
    Get offset of name metadata for go type at `ea`
    from recorded runtime module data

    :param ea: effective address of go type
    :param name_offset: recorded name offset for go type
                        (usually found in the `str` field
                         for the type)
    """
    types_soff = BADADDR
    for mod_soff, mod_eoff in GO_TYPES_RANGES:
        if ea >= mod_soff and ea < mod_eoff:
            types_soff = mod_soff
            break
    if types_soff != BADADDR:
        types_soff += name_offset
    return types_soff


def nameoff(name_offset, idx):
    return GO_TYPES_RANGES[idx][0] + name_offset


def get_raw_name_str(ea):
    """
    Get actual name string from name metadata at `ea`.
    See 

    :param ea: effective address of go name
    """
    name_len_hi = get_struct_val(ea, 'go_name.length_hi')
    name_len_lo = get_struct_val(ea, 'go_name.length_lo')
    name_len = (name_len_hi << 8) | name_len_lo
    return ida_bytes.get_strlit_contents(ea+3, name_len,
                                         ida_nalt.STRTYPE_C)


def get_type_name(ea):
    """
    Get name string from go type at `ea`

    :param ea: effective address of go type data
    """
    name_ea = get_moduledata_name_offset(ea,
                get_struct_val(ea, 'go_type0.str'))
    return get_raw_name_str(name_ea)


def resolve_moduledata_idx(ea):
    """
    Returns the index of which moduledata entry holds info
    for the address at `ea`. The index lines up with the
    prior declared go type (0 --> go_type0, 1 --> go_type1, etc.)

    :param ea: effective address
    """
    idx = 0
    for mod_soff, mod_eoff in GO_TYPES_RANGES:
        if ea >= mod_soff and ea < mod_eoff:
            return idx
        idx += 1

    raise Exception('Cannot get moduledata index for 0x%x' % ea)


def get_ida_struc_size(struct_name):
    """
    Returns the size of an IDA struct of the name `struct_name`.
    """
    type_id = ida_struct.get_struc_id(struct_name)
    type_sptr = ida_struct.get_struc(type_id)
    return ida_struct.get_struc_size(type_sptr)


def declare_interface(ea):
    """
    Creates and returns a structure that describes the interface
    at `ea` (which is assumed to be a go type for an interface).
    """
    kind = (get_struct_val(ea, 'go_type0.kind') & 0x1f)
    if kind != TYPEKIND_VALS['kindInterface'][0]:
        msg = 'type at 0x%s not an interface' % ea
        LOG.error(msg)
        raise Exception(msg)

    module_idx = resolve_moduledata_idx(ea)
    type_size = get_ida_struc_size('go_type0')
    tflag = (get_struct_val(ea, 'go_type0.tflag') & 0x7)

    iface_name = 'anonymous'
    if tflag & TYPE_TFLAGS['named']:
        iface_name = normalize_name(get_type_name(ea), ea,
                                    prepend_type_info=False)
        if tflag & TYPE_TFLAGS['extraStar']:
            iface_name = iface_name[1:]
        LOG.info('declare_interface: declaring iface %s at 0x%x',
                 iface_name, ea)

    iface_ea = ea + type_size
    iface_mhdr_ea = iface_ea + PTRSIZE
    mhdr_ea = get_struct_val(iface_mhdr_ea, 'go_slice.array')
    mhdr_len = get_struct_val(iface_mhdr_ea, 'go_slice.len')
    iface_methods = []
    for i in range(0, mhdr_len):
        mhdr_entry_ea = mhdr_ea + (i * PTRSIZE)
        imethod_struc_name = 'go_type%d_metadata_imethod' % module_idx
        imethod_struc_size = get_ida_struc_size(imethod_struc_name)
        name_offset = nameoff(
                get_struct_val(mhdr_entry_ea,
                               '%s.name' % imethod_struc_name),
                module_idx)
        imethod_name = get_raw_name_str(name_offset)
        LOG.info('found interface method %s.%s()',
                 iface_name, imethod_name)
        ida_bytes.del_items(mhdr_entry_ea, imethod_struc_size)
        ida_bytes.create_struct(mhdr_entry_ea,
                                imethod_struc_size,
                                ida_struct.get_struc_id(imethod_struc_name))
        iface_methods.append((
            normalize_name(imethod_name, None,
                           prepend_type_info=False),
            PTRSIZE,
            FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None
        ))

    itab_fields = [
        ('inter', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('_type', PTRSIZE, FF_PTR|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None, None),
        ('hash', 4, FF_DWORD|FF_DATA, None, None, None),
        ('_unused', 4, FF_DWORD|FF_DATA, None, None, None)
        ] + iface_methods
    LOG.debug('Creating new itab for %s', iface_name)
    create_and_populate_struct('go_itab__%s' % iface_name,
                               itab_fields)

    LOG.debug('Creating new iface for %s', iface_name)
    interface_tinfo = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(interface_tinfo,
                           idaapi.cvar.idati,
                           'go_itab__%s *;' % iface_name,
                           ida_typeinf.PT_TYP)
    iface_fields = [
        ('tab', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None),
        ('data', PTRSIZE, FF_PTR|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None, None)
        ]
    iface_tinfos = [interface_tinfo, None]
    iface_name = 'go_iface__%s' % iface_name
    create_and_populate_struct(iface_name,
                               iface_fields, None,
                               iface_tinfos)
    return iface_name


def create_structfields(ea, num_fields):
    """
    Parse member fields out of struct metadata starting at `ea`,
    including tags. Recursively creates new structures if needed.

    :param ea: effective address of struct metadata
               (see "go_type_metadata_struct" type)
    :param num_fields: number of fields at `ea`
    """
    structfield_id = ida_struct.get_struc_id('go_type_structfield')
    structfield_sptr = ida_struct.get_struc(structfield_id)
    structfield_size = ida_struct.get_struc_size(structfield_sptr)

    kind_datatypes = {
        TYPEKIND_VALS['kindSlice'][0]: 'go_slice',
        TYPEKIND_VALS['kindChan'][0]: FF_INT|FF_DATA,
        TYPEKIND_VALS['kindMap'][0]: 'go_hmap',
        TYPEKIND_VALS['kindString'][0]: 'go_string',
        TYPEKIND_VALS['kindFloat32'][0]: FF_FLOAT,
        TYPEKIND_VALS['kindFloat64'][0]: FF_DOUBLE,
        TYPEKIND_VALS['kindComplex64'][0]: 'go_complex64',
        TYPEKIND_VALS['kindComplex128'][0]: 'go_complex128',
        TYPEKIND_VALS['kindUnsafePointer'][0]: FF_PTR|FF_DATA|offflag()
        }
    fieldsize_to_typesize = {
        1: FF_BYTE,
        2: FF_WORD,
        4: FF_DWORD,
        8: FF_QWORD,
        16: FF_OWORD
        }
    fields = []
    tags = []
    tinfos = []
    for i in range(0, num_fields):
        fs_ea = ea + (i * structfield_size)
        ida_bytes.del_items(fs_ea, structfield_size)
        ida_bytes.create_struct(fs_ea, structfield_size,
                                structfield_id)
        fieldname_ea = get_struct_val(fs_ea,
                                      'go_type_structfield.name')

        success, fieldname_raw_str, tag, pkgpath = \
                get_name_info(fieldname_ea)

        fieldtype_ea = get_struct_val(fs_ea,
                                      'go_type_structfield.typ')
        fieldtype_size = get_struct_val(fieldtype_ea, 'go_type0.size')
        fieldoffset = get_struct_val(fs_ea,
                                     'go_type_structfield.offsetAnon')
        fieldoffset >>= 1
        fieldtype_kind = (get_struct_val(fieldtype_ea, 'go_type0.kind') \
                            & 0x1f)

        if fieldtype_size == 0:
            LOG.info('Skipping field %s (0 length)',
                     fieldname_raw_str)
            continue

        tags.append(tag)
        field_tinfo = None

        # TODO: pointers to structs? (mind those who reference
        # themselves in a linkedlist or tree like form)
        needs_offset = (fieldtype_kind in [TYPEKIND_VALS['kindPtr'][0],
                                           TYPEKIND_VALS['kindSlice'][0],
                                           TYPEKIND_VALS['kindUnsafePointer'][0]])

        invalid_names = ['sp']
        if fieldname_raw_str in invalid_names:
            fieldname_raw_str = '_' + fieldname_raw_str

        LOG.debug('field %s is type %d',
                  fieldname_raw_str, fieldtype_kind)

        # TODO: kindPtr pointing to correct structure
        if fieldtype_kind == TYPEKIND_VALS['kindArray'][0]:
            LOG.debug('creating new array at %x for field %s',
                      fieldtype_ea, fieldname_raw_str)
            # create a go struct of the type the array points to,
            # if needed.
            type_size = ida_struct.get_struc_size(
                    ida_struct.get_struc(ida_struct.get_struc_id('go_type0')))
            array_metadata_ea = fieldtype_ea + type_size
            array_len = get_struct_val(array_metadata_ea,
                                       'go_type_metadata_array.len')
            total_len = array_len
            array_elem_ea = get_struct_val(array_metadata_ea,
                                           'go_type_metadata_array.elem')
            array_elem_kind = (get_struct_val(array_elem_ea,
                                              'go_type0.kind') & 0x1f)
            array_elem_size = get_struct_val(array_elem_ea,
                                             'go_type0.size')
            full_member_size = array_len
            array_tinfo = ida_typeinf.tinfo_t()
            array_type_decl = ''
            fieldsize_to_decl = {
                1: '__int8',
                2: '__int16',
                4: '__int32',
                8: '__int64',
                16: '__int128'
                }

            while True:
                if array_elem_kind == TYPEKIND_VALS['kindArray'][0]:
                    # traverse through multi-dimensional arrays
                    array_type_decl = ('[%d]' % array_len) + array_type_decl
                    subarray_metadata_ea = array_elem_ea + type_size
                    array_elem_ea = get_struct_val(subarray_metadata_ea,
                                                   'go_type_metadata_array.elem')
                    array_elem_kind = (get_struct_val(
                        array_elem_ea, 'go_type0.kind') & 0x1f)
                    array_elem_size = get_struct_val(array_elem_ea,
                                                     'go_type0.size')
                    array_len = get_struct_val(subarray_metadata_ea,
                                               'go_type_metadata_array.len')
                    total_len = total_len * array_len
                    continue
                elif array_elem_kind == TYPEKIND_VALS['kindPtr'][0]:
                    array_type_decl = '*' + array_type_decl
                    subtype_metadata_ea = array_elem_ea + type_size
                    array_elem_ea = get_struct_val(subtype_metadata_ea,
                                                   'go_type_metadata_ptr._elem')
                    array_elem_kind = (get_struct_val(
                        array_elem_ea, 'go_type0.kind') & 0x1f)
                    array_elem_size = get_struct_val(array_elem_ea,
                                                     'go_type0.size')
                    continue
                elif array_elem_kind == TYPEKIND_VALS['kindStruct'][0]:
                    array_struct_mptr, array_struct_name = create_go_struct(array_elem_ea)
                    array_type_decl = array_struct_name + array_type_decl
                    fieldtype_size = array_struct_name
                    field_type_info = None
                    break
                elif array_elem_kind == TYPEKIND_VALS['kindInterface'][0]:
                    iface_name = declare_interface(array_elem_ea)
                    array_type_decl = iface_name + array_type_decl
                    fieldtype_size = iface_name
                    field_type_info = None
                    break
                elif array_elem_kind in kind_datatypes.keys():
                    field_type_info = kind_datatypes[array_elem_kind]
                    if type(field_type_info) in [str,unicode]:
                        array_type_decl = field_type_info + array_type_decl
                        fieldtype_size = field_type_info
                        field_type_info = None
                    else:
                        array_type_decl = fieldsize_to_decl[array_elem_size] + \
                                            array_type_decl
                        fieldtype_size = array_elem_size * total_len
                    break
                else:
                    array_type_decl = fieldsize_to_decl[array_elem_size] \
                                        + array_type_decl
                    field_type_info = fieldsize_to_typesize[array_elem_size] \
                                        | FF_DATA
                    fieldtype_size = array_elem_size * total_len
                    break

            array_type_decl += '[%d]' % array_len

            array_type_decl += ';'
            LOG.debug('array_type_decl for %s is %s',
                      fieldname_raw_str, array_type_decl)
            ida_typeinf.parse_decl(array_tinfo,
                                   idaapi.cvar.idati,
                                   array_type_decl,
                                   ida_typeinf.PT_TYP)
            field_tinfo = array_tinfo
        elif fieldtype_kind == TYPEKIND_VALS['kindStruct'][0]:
            LOG.debug('creating new struct at 0x%x for field %s',
                      fieldtype_ea, fieldname_raw_str)
            child_struct_mptr, child_struct_name = create_go_struct(fieldtype_ea)
            fieldtype_size = child_struct_name
            field_type_info = None
        elif fieldtype_kind == TYPEKIND_VALS['kindInterface'][0]:
            LOG.debug('creating new interface at 0x%x for field %s',
                      fieldtype_ea, fieldname_raw_str)
            iface_name = declare_interface(fieldtype_ea)
            fieldtype_size = iface_name
            field_type_info = None
        elif fieldtype_kind in kind_datatypes.keys():
            # pick a pre-selected struct or typeflags to represent the field
            field_type_info = kind_datatypes[fieldtype_kind]
            if type(field_type_info) in [str,unicode]:
                fieldtype_size = field_type_info
                field_type_info = None
        else:
            # just pick a type based on the size
            if fieldtype_size not in fieldsize_to_typesize.keys():
                msg = '%s (0x%x, %d bytes) not in fieldtype_size' % \
                        (fieldname_raw_str, fieldtype_ea, fieldtype_size)
                LOG.exception(msg)
                raise Exception(msg)
            field_type_info = fieldsize_to_typesize[fieldtype_size] \
                                | FF_DATA

        tinfos.append(field_tinfo)
        fields.append(
            (fieldname_raw_str, fieldtype_size, field_type_info,
                (OFF_CURRENT_SEGMENT if needs_offset else None),
                None, fieldoffset)
            )

    return fields, tags, tinfos
        


def populate_builtin_structs():
    """
    creates useful builtin/runtime structures
    """
    for struct_name, struct_data in GO_BUILTIN_STRUCTS:
        LOG.info('Adding struct %s...', struct_name)
        create_and_populate_struct(struct_name, struct_data)


## see https://github.com/golang/go/blob/release-branch.go1.12/src/runtime/symtab.go#L248

def find_runtime_firstmoduledata():
    """
    Finds first moduledata instance
    """
    return resolve_name('runtime.firstmoduledata')


def get_next_moduledata(ea):
    """
    Gets effective address of next moduledata instance

    :param ea: effective address of current moduledata
    """
    md_next_member = ida_struct.get_member_by_fullname(
                        'go_runtime_moduledata.next')[0]
    return ida_bytes.get_qword(ea + md_next_member.soff) \
            or BADADDR


def create_name(type_ea, type_struct):
    """
    declare a go_name type at 0x{type_ea} with metadata
    from type_struct (a go_type)

    return the following:
    (success, name value, tag value, pkgPath value)
    """

    name_struct_id = ida_struct.get_struc_id('go_name')
    str_member = ida_struct.get_member_by_name(type_struct, 'str')
    str_soff = str_member.soff
    name_offset = ida_bytes.get_dword(type_ea + str_soff)

    str_opinfo = idaapi.opinfo_t()
    ida_struct.retrieve_member_info(str_opinfo, str_member)
    types_base_ea = str_opinfo.ri.base

    name_ea = types_base_ea + name_offset
    success, str_value, tag_value, pkgPath_value = \
            get_name_info(name_ea)
    if get_struct_val(type_ea, 'go_type0.tflag') \
            & TYPE_TFLAGS['extraStar']:
        str_value = str_value[1:]

    # HACK: don't name it anything particular if it isn't
    # meant to be
    if (get_struct_val(type_ea, 'go_type0.tflag') \
            & TYPE_TFLAGS['named']) == 0:
        str_value = 'anonymous_type_%x' % type_ea

    if not success:
        LOG.error('could not get name info at %x',
                  name_ea)
        return (False, None, None, None)

    name_struct_len = 3 + len(str_value)
    LOG.debug('creating go_name of size %d at 0x%x',
              name_struct_len, name_ea)

    if not ida_bytes.del_items(name_ea, 0, name_struct_len):
        LOG.error('failed to undefine data for go_name ' \
                  'at 0x%x', name_ea)
        return (False, None, None, None)
    if not ida_bytes.create_struct(name_ea, name_struct_len,
                                   name_struct_id):
        LOG.error('failed to create go_name struct at ' \
                  '0x%x', name_ea)
        return (False, None, None, None)

    set_name(name_ea, 'go_name__' + normalize_name(str_value, type_ea))

    return (True, str_value, tag_value, pkgPath_value)


def get_name_info(name_ea):
    """
    Get name and optionally tag and pkgPath strings
    from name import metadata at `name_ea`

    :param name_ea: effective address of name metadata
    """
    str_value = tag_value = pkgPath_value = None

    name_flags = get_byte(name_ea)

    # (go_name.length_hi << 8) | go_name.length_lo
    str_len = \
            ((ida_bytes.get_byte(name_ea + 1) << 8) & 0xffff) | \
             (ida_bytes.get_byte(name_ea + 2) & 0xffff)

    str_value = ida_bytes.get_strlit_contents(name_ea+3, str_len, 0)

    if get_struct_val(name_ea, 'go_name.flags') & \
            NAME_FLAGS['tagFollowsName']:
        tag_ea = name_ea + 3 + str_len
        tag_len = \
                ((ida_bytes.get_byte(tag_ea) << 8) & 0xffff) | \
                 (ida_bytes.get_byte(tag_ea + 1) & 0xffff)
        if tag_len > 0:
            LOG.debug('0x%x contains %d byte long tag',
                      tag_ea, tag_len)
            tag_value = ida_bytes.get_strlit_contents(tag_ea+2, tag_len, 0)
            LOG.debug('tag: %s', tag_value)

    # TODO: pkgPath

    return (True, str_value, tag_value, pkgPath_value)


def create_go_type_struct(idx, types_ea):
    """
    Creates a new go type structure from moduledata described
    at `types_ea`.

    A different go type structure is created for every
    moduledata instance so it has the right user offset
    for the `str` and `ptrToThis` fields.

    :param idx: moduledata index (firstmoduledata starts at 0)
    :param types_ea: effective address of moduledata
    """
    go_type_name = 'go_type%d' % idx
    types_opinfo = idaapi.opinfo_t()
    types_opinfo.ri.base = types_ea
    types_opinfo.ri.target = BADADDR
    types_opinfo.ri.tdelta = 0
    types_opinfo.ri.flags = ida_nalt.REF_OFF64
    go_type_spec = [
        ('size', PTRSIZE, FF_QWORD|FF_DATA, None, None, None),
        ('ptrdata', PTRSIZE, FF_QWORD|FF_DATA, None, None, None),
        ('hash', 4, FF_DWORD|FF_DATA, None, None, None),
        ('tflag', 1, FF_BYTE|FF_DATA, None, 'go_tflag', None),
        ('align', 1, FF_BYTE|FF_DATA, None, None, None),
        ('fieldalign', 1, FF_BYTE|FF_DATA, None, None, None),
        ('kind', 1, FF_BYTE|FF_DATA, None, 'go_typekind', None),
        ('alg', PTRSIZE, FF_QWORD|FF_DATA, None, None, None),
        ('gcdata', PTRSIZE, FF_QWORD|FF_DATA, None, None, None),
        ('str', 4, FF_DWORD|FF_DATA|offflag(), types_opinfo, None, None),
        ('ptrToThis', 4, FF_DWORD|FF_DATA|offflag(), types_opinfo,
            None, None)
        ]
    return create_and_populate_struct(go_type_name, go_type_spec)


def create_uncommon_struct(idx, types_ea):
    """
    Creates a struct used to describe uncommon type metadata.
    Like with go_type, uncommon metadata has fields with a
    moduledata-dependent user offset.

    :param idx: moduledata index (firstmoduledata starts at 0)
    :param types_ea: effective address of moduledata typedata
    """
    struct_name = 'go_type%d_metadata_uncommon' % idx
    types_opinfo = idaapi.opinfo_t()
    types_opinfo.ri.base = types_ea
    types_opinfo.ri.target = BADADDR
    types_opinfo.ri.tdelta = 0
    types_opinfo.ri.flags = ida_nalt.REF_OFF64
    struct_spec = [
        ('pkgPath', 4, FF_DWORD|FF_DATA|offflag(), types_opinfo, None,
            None),
        ('mcount', 2, FF_WORD|FF_DATA, None, None, None),
        ('xcount', 2, FF_WORD|FF_DATA, None, None, None),
        ('moff', 4, FF_DWORD|FF_DATA, None, None, None),
        ('_unused', 4, FF_DWORD|FF_DATA, None, None, None)
        ]
    return create_and_populate_struct(struct_name, struct_spec)


def create_method_struct(idx, types_ea, text_ea):
    """
    Creates a new method type struct (used to describe
    struct-specific methods). Like with go_type, method
    structs have fields with a moduledata-dependent user offset.

    :param idx: moduledata index (firstmoduledata starts at 0)
    :param types_ea: effective address of moduledata typedata
    :param text_ea: effective address of moduledata text section
    """
    struct_name = 'go_type%d_metadata_method' % idx

    nameOff_opinfo = idaapi.opinfo_t()
    nameOff_opinfo.ri.base = types_ea
    nameOff_opinfo.ri.target = BADADDR
    nameOff_opinfo.ri.tdelta = 0
    nameOff_opinfo.ri.flags = ida_nalt.REF_OFF32

    textOff_opinfo = idaapi.opinfo_t()
    textOff_opinfo.ri.base = text_ea
    textOff_opinfo.ri.target = BADADDR
    textOff_opinfo.ri.tdelta = 0
    textOff_opinfo.ri.flags = ida_nalt.REF_OFF32

    go_imethod_spec = [
        ('name', 4, FF_DWORD|FF_DATA|offflag(), nameOff_opinfo, None,
            None),
        ('typ', 4, FF_DWORD|FF_DATA|offflag(), nameOff_opinfo, None,
            None),
        ('ifn', 4, FF_DWORD|FF_DATA|offflag(), textOff_opinfo, None,
            None),
        ('tfn', 4, FF_DWORD|FF_DATA|offflag(), textOff_opinfo, None,
            None)
        ]
    return create_and_populate_struct(struct_name, go_imethod_spec)


def create_imethod_struct(idx, types_ea):
    """
    Creates a new imethod tpe struct (used to describe
    interface-specific methods). Like with go_type, imethod
    structs have fields with a moduledata-dependent user offset.

    :param idx: moduledata index (firstmoduledata starts at 0)
    :param types_ea: effective address of moduledata typedata
    """
    imethod_name = 'go_type%d_metadata_imethod' % idx
    types_opinfo = idaapi.opinfo_t()
    types_opinfo.ri.base = types_ea
    types_opinfo.ri.target = BADADDR
    types_opinfo.ri.tdelta = 0
    types_opinfo.ri.flags = ida_nalt.REF_OFF64
    go_imethod_spec = [
        ('name', 4, FF_DWORD|FF_DATA|offflag(), types_opinfo, None, None),
        ('ityp', 4, FF_DWORD|FF_DATA|offflag(), types_opinfo, None, None)
        ]
    return create_and_populate_struct(imethod_name, go_imethod_spec)


def main():
    LOG.info('populating built-in bitfields...')
    populate_builtin_bitfields()

    LOG.info('populating built-in runtime structs...')
    populate_builtin_structs()

    LOG.info('finding and declaring moduledata structs...')
    moduledata_ea = find_runtime_firstmoduledata()
    if moduledata_ea == BADADDR:
        LOG.error('could not find runtime.firstmoduledata...')
        return

    # enumerate all moduledata structs in the noptrdata section
    # starting with runtime.firstmoduledata
    moduledata_struct_id = ida_struct.get_struc_id('go_runtime_moduledata')
    idx = 0
    if moduledata_struct_id != BADADDR:
        moduledata_size = ida_struct.get_struc_size(
                            ida_struct.get_struc(moduledata_struct_id))
        types_struct_offset = ida_struct.get_member_by_fullname(
                                    'go_runtime_moduledata.types')[0].soff
        etypes_struct_offset = ida_struct.get_member_by_fullname(
                                    'go_runtime_moduledata.etypes')[0].soff

        while moduledata_ea != BADADDR:
            LOG.info('found moduledata at 0x%x', moduledata_ea)
            if not ida_bytes.del_items(moduledata_ea, 0,
                                       moduledata_size):
                LOG.error('could not undefine byte range for ' \
                          'moduledata at 0x%x', moduledata_ea)
                return
            if not ida_bytes.create_struct(moduledata_ea, moduledata_size,
                                           moduledata_struct_id):
                LOG.error('could not create moduledata struct at ' \
                          '0x%x', moduledata_ea)
                return

            types_offset = ida_bytes.get_qword(
                    moduledata_ea + types_struct_offset)
            etypes_offset = ida_bytes.get_qword(
                    moduledata_ea + etypes_struct_offset)
            GO_TYPES_RANGES.append( (types_offset,etypes_offset) )

            # create a different type struct for each moduledata instance
            # found in the rodata section ("go_type0", "go_type1", etc.).
            # The name and type offsets in the go_type struct rely on that
            # particular offset
            LOG.info('Creating go_type struct out of offset 0x%x',
                     types_offset)
            create_go_type_struct(idx, types_offset)
            # create first go_type struct before creating a method to
            # have a cheese-o way to get the text section start
            text_start_ea = get_struct_val(moduledata_ea,
                                           'go_runtime_moduledata.text')
            create_uncommon_struct(idx, types_offset)
            create_imethod_struct(idx, types_offset)
            create_method_struct(idx, types_offset, text_start_ea)
            moduledata_ea = get_next_moduledata(moduledata_ea)
            idx += 1

    LOG.info('renaming and mapping out type structs...')
    try:
        types_parsed, structs_created = map_type_structs()
        # TODO: painfully miscounted
        LOG.info('parsed %d types', types_parsed)
        LOG.info('created %d structs', structs_created)
    except Exception as ex:
        LOG.error('bad things happened')
        LOG.exception(ex)
        raise


if __name__ == '__main__':
    main()
