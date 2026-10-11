"""DEX opcode 定义表 - 完整的 Dalvik 指令集"""
from enum import IntEnum

class Opcode(IntEnum):
    NOP = 0x00; MOVE = 0x01; MOVE_FROM16 = 0x02; MOVE_16 = 0x03
    MOVE_WIDE = 0x04; MOVE_WIDE_FROM16 = 0x05; MOVE_WIDE_16 = 0x06
    MOVE_OBJECT = 0x07; MOVE_OBJECT_FROM16 = 0x08; MOVE_OBJECT_16 = 0x09
    MOVE_RESULT = 0x0a; MOVE_RESULT_WIDE = 0x0b; MOVE_RESULT_OBJECT = 0x0c
    MOVE_EXCEPTION = 0x0d; RETURN_VOID = 0x0e; RETURN = 0x0f
    RETURN_WIDE = 0x10; RETURN_OBJECT = 0x11; CONST_4 = 0x12
    CONST_16 = 0x13; CONST = 0x14; CONST_HIGH16 = 0x15
    CONST_WIDE_16 = 0x16; CONST_WIDE_32 = 0x17; CONST_WIDE = 0x18
    CONST_WIDE_HIGH16 = 0x19; CONST_STRING = 0x1a; CONST_STRING_JUMBO = 0x1b
    CONST_CLASS = 0x1c; MONITOR_ENTER = 0x1d; MONITOR_EXIT = 0x1e
    CHECK_CAST = 0x1f; INSTANCE_OF = 0x20; ARRAY_LENGTH = 0x21
    NEW_INSTANCE = 0x22; NEW_ARRAY = 0x23; FILLED_NEW_ARRAY = 0x24
    FILLED_NEW_ARRAY_RANGE = 0x25; FILL_ARRAY_DATA = 0x26; THROW = 0x27
    GOTO = 0x28; GOTO_16 = 0x29; GOTO_32 = 0x2a
    PACKED_SWITCH = 0x2b; SPARSE_SWITCH = 0x2c
    CMPL_FLOAT = 0x2d; CMPG_FLOAT = 0x2e; CMPL_DOUBLE = 0x2f; CMPG_DOUBLE = 0x30
    CMP_LONG = 0x31
    IF_EQ = 0x32; IF_NE = 0x33; IF_LT = 0x34; IF_GE = 0x35; IF_GT = 0x36; IF_LE = 0x37
    IF_EQZ = 0x38; IF_NEZ = 0x39; IF_LTZ = 0x3a; IF_GEZ = 0x3b; IF_GTZ = 0x3c; IF_LEZ = 0x3d
    AGET = 0x44; AGET_WIDE = 0x45; AGET_OBJECT = 0x46; AGET_BOOLEAN = 0x47
    AGET_BYTE = 0x48; AGET_CHAR = 0x49; AGET_SHORT = 0x4a
    APUT = 0x4b; APUT_WIDE = 0x4c; APUT_OBJECT = 0x4d; APUT_BOOLEAN = 0x4e
    APUT_BYTE = 0x4f; APUT_CHAR = 0x50; APUT_SHORT = 0x51
    IGET = 0x52; IGET_WIDE = 0x53; IGET_OBJECT = 0x54; IGET_BOOLEAN = 0x55
    IGET_BYTE = 0x56; IGET_CHAR = 0x57; IGET_SHORT = 0x58
    IPUT = 0x59; IPUT_WIDE = 0x5a; IPUT_OBJECT = 0x5b; IPUT_BOOLEAN = 0x5c
    IPUT_BYTE = 0x5d; IPUT_CHAR = 0x5e; IPUT_SHORT = 0x5f
    SGET = 0x60; SGET_WIDE = 0x61; SGET_OBJECT = 0x62; SGET_BOOLEAN = 0x63
    SGET_BYTE = 0x64; SGET_CHAR = 0x65; SGET_SHORT = 0x66
    SPUT = 0x67; SPUT_WIDE = 0x68; SPUT_OBJECT = 0x69; SPUT_BOOLEAN = 0x6a
    SPUT_BYTE = 0x6b; SPUT_CHAR = 0x6c; SPUT_SHORT = 0x6d
    INVOKE_VIRTUAL = 0x6e; INVOKE_SUPER = 0x6f; INVOKE_DIRECT = 0x70
    INVOKE_STATIC = 0x71; INVOKE_INTERFACE = 0x72
    INVOKE_VIRTUAL_RANGE = 0x74; INVOKE_SUPER_RANGE = 0x75
    INVOKE_DIRECT_RANGE = 0x76; INVOKE_STATIC_RANGE = 0x77; INVOKE_INTERFACE_RANGE = 0x78
    NEG_INT = 0x7b; NOT_INT = 0x7c; NEG_LONG = 0x7d; NOT_LONG = 0x7e
    NEG_FLOAT = 0x7f; NEG_DOUBLE = 0x80
    INT_TO_LONG = 0x81; INT_TO_FLOAT = 0x82; INT_TO_DOUBLE = 0x83
    LONG_TO_INT = 0x84; LONG_TO_FLOAT = 0x85; LONG_TO_DOUBLE = 0x86
    FLOAT_TO_INT = 0x87; FLOAT_TO_LONG = 0x88; FLOAT_TO_DOUBLE = 0x89
    DOUBLE_TO_INT = 0x8a; DOUBLE_TO_LONG = 0x8b; DOUBLE_TO_FLOAT = 0x8c
    INT_TO_BYTE = 0x8d; INT_TO_CHAR = 0x8e; INT_TO_SHORT = 0x8f
    ADD_INT = 0x90; SUB_INT = 0x91; MUL_INT = 0x92; DIV_INT = 0x93; REM_INT = 0x94
    AND_INT = 0x95; OR_INT = 0x96; XOR_INT = 0x97; SHL_INT = 0x98; SHR_INT = 0x99; USHR_INT = 0x9a
    ADD_LONG = 0x9b; SUB_LONG = 0x9c; MUL_LONG = 0x9d; DIV_LONG = 0x9e; REM_LONG = 0x9f
    AND_LONG = 0xa0; OR_LONG = 0xa1; XOR_LONG = 0xa2; SHL_LONG = 0xa3; SHR_LONG = 0xa4; USHR_LONG = 0xa5
    ADD_FLOAT = 0xa6; SUB_FLOAT = 0xa7; MUL_FLOAT = 0xa8; DIV_FLOAT = 0xa9; REM_FLOAT = 0xaa
    ADD_DOUBLE = 0xab; SUB_DOUBLE = 0xac; MUL_DOUBLE = 0xad; DIV_DOUBLE = 0xae; REM_DOUBLE = 0xaf
    ADD_INT_2ADDR = 0xb0; SUB_INT_2ADDR = 0xb1; MUL_INT_2ADDR = 0xb2; DIV_INT_2ADDR = 0xb3; REM_INT_2ADDR = 0xb4
    AND_INT_2ADDR = 0xb5; OR_INT_2ADDR = 0xb6; XOR_INT_2ADDR = 0xb7; SHL_INT_2ADDR = 0xb8; SHR_INT_2ADDR = 0xb9; USHR_INT_2ADDR = 0xba
    ADD_LONG_2ADDR = 0xbb; SUB_LONG_2ADDR = 0xbc; MUL_LONG_2ADDR = 0xbd; DIV_LONG_2ADDR = 0xbe; REM_LONG_2ADDR = 0xbf
    AND_LONG_2ADDR = 0xc0; OR_LONG_2ADDR = 0xc1; XOR_LONG_2ADDR = 0xc2; SHL_LONG_2ADDR = 0xc3; SHR_LONG_2ADDR = 0xc4; USHR_LONG_2ADDR = 0xc5
    ADD_FLOAT_2ADDR = 0xc6; SUB_FLOAT_2ADDR = 0xc7; MUL_FLOAT_2ADDR = 0xc8; DIV_FLOAT_2ADDR = 0xc9; REM_FLOAT_2ADDR = 0xca
    ADD_DOUBLE_2ADDR = 0xcb; SUB_DOUBLE_2ADDR = 0xcc; MUL_DOUBLE_2ADDR = 0xcd; DIV_DOUBLE_2ADDR = 0xce; REM_DOUBLE_2ADDR = 0xcf
    ADD_INT_LIT16 = 0xd0; RSUB_INT = 0xd1; MUL_INT_LIT16 = 0xd2; DIV_INT_LIT16 = 0xd3; REM_INT_LIT16 = 0xd4
    AND_INT_LIT16 = 0xd5; OR_INT_LIT16 = 0xd6; XOR_INT_LIT16 = 0xd7
    ADD_INT_LIT8 = 0xd8; RSUB_INT_LIT8 = 0xd9; MUL_INT_LIT8 = 0xda; DIV_INT_LIT8 = 0xdb; REM_INT_LIT8 = 0xdc
    AND_INT_LIT8 = 0xdd; OR_INT_LIT8 = 0xde; XOR_INT_LIT8 = 0xdf
    SHL_INT_LIT8 = 0xe0; SHR_INT_LIT8 = 0xe1; USHR_INT_LIT8 = 0xe2

# (opcode, name, format, size_in_code_units)
OPCODE_FORMAT = {
    0x00: ('nop', '10x', 1), 0x01: ('move', '12x', 1), 0x02: ('move/from16', '22x', 2), 0x03: ('move/16', '32x', 3),
    0x04: ('move-wide', '12x', 1), 0x05: ('move-wide/from16', '22x', 2), 0x06: ('move-wide/16', '32x', 3),
    0x07: ('move-object', '12x', 1), 0x08: ('move-object/from16', '22x', 2), 0x09: ('move-object/16', '32x', 3),
    0x0a: ('move-result', '11x', 1), 0x0b: ('move-result-wide', '11x', 1), 0x0c: ('move-result-object', '11x', 1),
    0x0d: ('move-exception', '11x', 1), 0x0e: ('return-void', '10x', 1), 0x0f: ('return', '11x', 1),
    0x10: ('return-wide', '11x', 1), 0x11: ('return-object', '11x', 1), 0x12: ('const/4', '11n', 1),
    0x13: ('const/16', '21s', 2), 0x14: ('const', '31i', 3), 0x15: ('const/high16', '21h', 2),
    0x16: ('const-wide/16', '21s', 2), 0x17: ('const-wide/32', '31i', 3), 0x18: ('const-wide', '51l', 5),
    0x19: ('const-wide/high16', '21h', 2), 0x1a: ('const-string', '21c', 2), 0x1b: ('const-string/jumbo', '31c', 3),
    0x1c: ('const-class', '21c', 2), 0x1d: ('monitor-enter', '11x', 1), 0x1e: ('monitor-exit', '11x', 1),
    0x1f: ('check-cast', '21c', 2), 0x20: ('instance-of', '22c', 2), 0x21: ('array-length', '12x', 1),
    0x22: ('new-instance', '21c', 2), 0x23: ('new-array', '22c', 2), 0x24: ('filled-new-array', '35c', 3),
    0x25: ('filled-new-array/range', '3rc', 3), 0x26: ('fill-array-data', '31t', 3), 0x27: ('throw', '11x', 1),
    0x28: ('goto', '10t', 1), 0x29: ('goto/16', '20t', 2), 0x2a: ('goto/32', '30t', 3),
    0x2b: ('packed-switch', '31t', 3), 0x2c: ('sparse-switch', '31t', 3),
    0x2d: ('cmpl-float', '23x', 2), 0x2e: ('cmpg-float', '23x', 2), 0x2f: ('cmpl-double', '23x', 2),
    0x30: ('cmpg-double', '23x', 2), 0x31: ('cmp-long', '23x', 2),
    0x32: ('if-eq', '22t', 2), 0x33: ('if-ne', '22t', 2), 0x34: ('if-lt', '22t', 2),
    0x35: ('if-ge', '22t', 2), 0x36: ('if-gt', '22t', 2), 0x37: ('if-le', '22t', 2),
    0x38: ('if-eqz', '21t', 2), 0x39: ('if-nez', '21t', 2), 0x3a: ('if-ltz', '21t', 2),
    0x3b: ('if-gez', '21t', 2), 0x3c: ('if-gtz', '21t', 2), 0x3d: ('if-lez', '21t', 2),
    0x44: ('aget', '23x', 2), 0x45: ('aget-wide', '23x', 2), 0x46: ('aget-object', '23x', 2),
    0x47: ('aget-boolean', '23x', 2), 0x48: ('aget-byte', '23x', 2), 0x49: ('aget-char', '23x', 2), 0x4a: ('aget-short', '23x', 2),
    0x4b: ('aput', '23x', 2), 0x4c: ('aput-wide', '23x', 2), 0x4d: ('aput-object', '23x', 2),
    0x4e: ('aput-boolean', '23x', 2), 0x4f: ('aput-byte', '23x', 2), 0x50: ('aput-char', '23x', 2), 0x51: ('aput-short', '23x', 2),
    0x52: ('iget', '22c', 2), 0x53: ('iget-wide', '22c', 2), 0x54: ('iget-object', '22c', 2),
    0x55: ('iget-boolean', '22c', 2), 0x56: ('iget-byte', '22c', 2), 0x57: ('iget-char', '22c', 2), 0x58: ('iget-short', '22c', 2),
    0x59: ('iput', '22c', 2), 0x5a: ('iput-wide', '22c', 2), 0x5b: ('iput-object', '22c', 2),
    0x5c: ('iput-boolean', '22c', 2), 0x5d: ('iput-byte', '22c', 2), 0x5e: ('iput-char', '22c', 2), 0x5f: ('iput-short', '22c', 2),
    0x60: ('sget', '21c', 2), 0x61: ('sget-wide', '21c', 2), 0x62: ('sget-object', '21c', 2),
    0x63: ('sget-boolean', '21c', 2), 0x64: ('sget-byte', '21c', 2), 0x65: ('sget-char', '21c', 2), 0x66: ('sget-short', '21c', 2),
    0x67: ('sput', '21c', 2), 0x68: ('sput-wide', '21c', 2), 0x69: ('sput-object', '21c', 2),
    0x6a: ('sput-boolean', '21c', 2), 0x6b: ('sput-byte', '21c', 2), 0x6c: ('sput-char', '21c', 2), 0x6d: ('sput-short', '21c', 2),
    0x6e: ('invoke-virtual', '35c', 3), 0x6f: ('invoke-super', '35c', 3), 0x70: ('invoke-direct', '35c', 3),
    0x71: ('invoke-static', '35c', 3), 0x72: ('invoke-interface', '35c', 3),
    0x74: ('invoke-virtual/range', '3rc', 3), 0x75: ('invoke-super/range', '3rc', 3),
    0x76: ('invoke-direct/range', '3rc', 3), 0x77: ('invoke-static/range', '3rc', 3), 0x78: ('invoke-interface/range', '3rc', 3),
    0x7b: ('neg-int', '12x', 1), 0x7c: ('not-int', '12x', 1), 0x7d: ('neg-long', '12x', 1), 0x7e: ('not-long', '12x', 1),
    0x7f: ('neg-float', '12x', 1), 0x80: ('neg-double', '12x', 1),
    0x81: ('int-to-long', '12x', 1), 0x82: ('int-to-float', '12x', 1), 0x83: ('int-to-double', '12x', 1),
    0x84: ('long-to-int', '12x', 1), 0x85: ('long-to-float', '12x', 1), 0x86: ('long-to-double', '12x', 1),
    0x87: ('float-to-int', '12x', 1), 0x88: ('float-to-long', '12x', 1), 0x89: ('float-to-double', '12x', 1),
    0x8a: ('double-to-int', '12x', 1), 0x8b: ('double-to-long', '12x', 1), 0x8c: ('double-to-float', '12x', 1),
    0x8d: ('int-to-byte', '12x', 1), 0x8e: ('int-to-char', '12x', 1), 0x8f: ('int-to-short', '12x', 1),
    0x90: ('add-int', '23x', 2), 0x91: ('sub-int', '23x', 2), 0x92: ('mul-int', '23x', 2), 0x93: ('div-int', '23x', 2), 0x94: ('rem-int', '23x', 2),
    0x95: ('and-int', '23x', 2), 0x96: ('or-int', '23x', 2), 0x97: ('xor-int', '23x', 2), 0x98: ('shl-int', '23x', 2), 0x99: ('shr-int', '23x', 2), 0x9a: ('ushr-int', '23x', 2),
    0x9b: ('add-long', '23x', 2), 0x9c: ('sub-long', '23x', 2), 0x9d: ('mul-long', '23x', 2), 0x9e: ('div-long', '23x', 2), 0x9f: ('rem-long', '23x', 2),
    0xa0: ('and-long', '23x', 2), 0xa1: ('or-long', '23x', 2), 0xa2: ('xor-long', '23x', 2), 0xa3: ('shl-long', '23x', 2), 0xa4: ('shr-long', '23x', 2), 0xa5: ('ushr-long', '23x', 2),
    0xa6: ('add-float', '23x', 2), 0xa7: ('sub-float', '23x', 2), 0xa8: ('mul-float', '23x', 2), 0xa9: ('div-float', '23x', 2), 0xaa: ('rem-float', '23x', 2),
    0xab: ('add-double', '23x', 2), 0xac: ('sub-double', '23x', 2), 0xad: ('mul-double', '23x', 2), 0xae: ('div-double', '23x', 2), 0xaf: ('rem-double', '23x', 2),
    0xb0: ('add-int/2addr', '12x', 1), 0xb1: ('sub-int/2addr', '12x', 1), 0xb2: ('mul-int/2addr', '12x', 1), 0xb3: ('div-int/2addr', '12x', 1), 0xb4: ('rem-int/2addr', '12x', 1),
    0xb5: ('and-int/2addr', '12x', 1), 0xb6: ('or-int/2addr', '12x', 1), 0xb7: ('xor-int/2addr', '12x', 1), 0xb8: ('shl-int/2addr', '12x', 1), 0xb9: ('shr-int/2addr', '12x', 1), 0xba: ('ushr-int/2addr', '12x', 1),
    0xbb: ('add-long/2addr', '12x', 1), 0xbc: ('sub-long/2addr', '12x', 1), 0xbd: ('mul-long/2addr', '12x', 1), 0xbe: ('div-long/2addr', '12x', 1), 0xbf: ('rem-long/2addr', '12x', 1),
    0xc0: ('and-long/2addr', '12x', 1), 0xc1: ('or-long/2addr', '12x', 1), 0xc2: ('xor-long/2addr', '12x', 1), 0xc3: ('shl-long/2addr', '12x', 1), 0xc4: ('shr-long/2addr', '12x', 1), 0xc5: ('ushr-long/2addr', '12x', 1),
    0xc6: ('add-float/2addr', '12x', 1), 0xc7: ('sub-float/2addr', '12x', 1), 0xc8: ('mul-float/2addr', '12x', 1), 0xc9: ('div-float/2addr', '12x', 1), 0xca: ('rem-float/2addr', '12x', 1),
    0xcb: ('add-double/2addr', '12x', 1), 0xcc: ('sub-double/2addr', '12x', 1), 0xcd: ('mul-double/2addr', '12x', 1), 0xce: ('div-double/2addr', '12x', 1), 0xcf: ('rem-double/2addr', '12x', 1),
    0xd0: ('add-int/lit16', '22s', 2), 0xd1: ('rsub-int', '22s', 2), 0xd2: ('mul-int/lit16', '22s', 2),
    0xd3: ('div-int/lit16', '22s', 2), 0xd4: ('rem-int/lit16', '22s', 2),
    0xd5: ('and-int/lit16', '22s', 2), 0xd6: ('or-int/lit16', '22s', 2), 0xd7: ('xor-int/lit16', '22s', 2),
    0xd8: ('add-int/lit8', '22b', 2), 0xd9: ('rsub-int/lit8', '22b', 2), 0xda: ('mul-int/lit8', '22b', 2),
    0xdb: ('div-int/lit8', '22b', 2), 0xdc: ('rem-int/lit8', '22b', 2),
    0xdd: ('and-int/lit8', '22b', 2), 0xde: ('or-int/lit8', '22b', 2), 0xdf: ('xor-int/lit8', '22b', 2),
    0xe0: ('shl-int/lit8', '22b', 2), 0xe1: ('shr-int/lit8', '22b', 2), 0xe2: ('ushr-int/lit8', '22b', 2),
}

# 指令分类
INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
FIELD_OPS = {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
             0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d}
CONST_OPS = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c}
RETURN_OPS = {0x0e, 0x0f, 0x10, 0x11}
IF_OPS = {0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d}
GOTO_OPS = {0x28, 0x29, 0x2a}
SWITCH_OPS = {0x2b, 0x2c}
NEW_OPS = {0x22, 0x23, 0x24, 0x25}
ARRAY_OPS = {0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51}

OPCODE_NAMES = {op: name for op, (name, fmt, size) in OPCODE_FORMAT.items()}

def get_opcode_name(opcode):
    info = OPCODE_FORMAT.get(opcode)
    return info[0] if info else f'unknown_0x{opcode:02x}'

def get_opcode_format(opcode):
    info = OPCODE_FORMAT.get(opcode)
    return info[1] if info else 'unknown'

def get_opcode_size(opcode):
    info = OPCODE_FORMAT.get(opcode)
    return info[2] if info else 1

def is_invoke(opcode): return opcode in INVOKE_OPS
def is_field_access(opcode): return opcode in FIELD_OPS
def is_const(opcode): return opcode in CONST_OPS
def is_return(opcode): return opcode in RETURN_OPS
def is_if(opcode): return opcode in IF_OPS
def is_goto(opcode): return opcode in GOTO_OPS
def is_switch(opcode): return opcode in SWITCH_OPS
def is_new(opcode): return opcode in NEW_OPS
def is_array(opcode): return opcode in ARRAY_OPS
def is_branch(opcode): return opcode in IF_OPS | GOTO_OPS | SWITCH_OPS
def is_terminator(opcode):
    """是否为基本块终结指令"""
    return opcode in RETURN_OPS or opcode == 0x27 or opcode in GOTO_OPS

