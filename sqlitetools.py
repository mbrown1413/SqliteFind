"""
Parsing tools for sqlite3 records.

https://www.sqlite.org/fileformat2.html#record_format
"""

import struct

class RecordFormatError(Exception):
    pass

def parse_record(buf, start=0, n_cols=None, expected_types=None):
    i = start  # i always points to the next byte in buf to parse

    # Payload length
    payload_len, l = parse_varint(buf, i)
    i += l

    # Row ID
    row_id, l = parse_varint(buf, i)
    i += l

    # Header length
    header_start = i
    header_len, l = parse_varint(buf, i)
    i += l

    if header_len < 2:
        raise RecordFormatError("Header length {} too small".format(header_len))
    if n_cols is not None:
        # Each varint takes 1 to 9 bytes. There is one varint storing the
        # header length, then one for each column.
        max_header_len = 9 * (1 + n_cols)
        min_header_len = 1 * (1 + n_cols)
        if header_len > max_header_len:
            raise RecordFormatError("Header length of {} is too long for {} cols".format(header_len, n_cols))
        if header_len < min_header_len:
            raise RecordFormatError("Header length of {} too short for {} cols".format(header_len, n_cols))

    # Column types
    serial_types = []
    while i < header_start + header_len:
        stype, l = parse_varint(buf, i)
        i += l
        serial_types.append(stype)

    if i != header_start + header_len:
        raise RecordFormatError("Record header was not the correct length.")
    if n_cols is not None and len(serial_types) != n_cols:
        raise RecordFormatError("Expected {} columns, got "
                "{}".format(n_cols, len(serial_types)))
    if expected_types is not None:
        for n, (serial_type, expected_type_set) in enumerate(zip(serial_types, expected_types)):
            if expected_type is not None and serial_type not in expected_type_set:
                raise RecordFormatError("Serial type for col {} was {}, not one of the expected {}".format(n, serial_type, expected_type))

    # Parse columns
    values = []
    for stype in serial_types:
        value, l = parse_column(stype, buf, i)
        i += l
        values.append(value)

    actual_payload_len = i-(start+2)  # -2 since payload_len does not include payload_len and row_id
    if actual_payload_len != payload_len:  
        raise RecordFormatError("Payload length field does not match actual length of payload. payload_len={}, actual length={}".format(payload_len, actual_payload_len))

    return serial_types, values

def count_varints(buf, start, n, backward=False):
    if not backward:
        raise NotImplementedError()

    pos = start
    for i in range(n):
        pos -= 1

        # If the last byte of a varint has bit 0x80 set, it must be a nine byte
        # varint. 
        nine_byte = False
        if ord(buf[pos]) & 0x80:
            nine_byte = True

        for j in range(8):
            if ord(buf[pos-1]) & 0x80 != 0x80:
                break
            pos -= 1

        if nine_byte and j+1 != 9:
            raise RecordFormatError("Varint ended with 0x80 bit set but was not 9 bytes.")

    return pos

def parse_varint(buf, start=0):
    """Returns (integer value, size of varint 1-9)."""
    bits = []
    for i in range(9):
        if start+i >= len(buf):
            raise RecordFormatError("Ran off end of buffer while reading varint")
        byte = ord(buf[start+i])

        # Lower 7 bits are part of the int value
        # Last byte all 8 bits are part of the int value
        for j in range(8 if i==8 else 6, -1, -1):
            bits.append((byte >> j) & 1)

        # Highest bit indicates if there is another byte following
        if byte & 0x80 != 0x80:  # No more bytes
            break

    x = int(''.join(map(str, bits)), 2)  # Convert bits into an integer
    return twos_comp(x, 64), i+1

def encode_varint(i):
    varint_bits = []
    i_bits = encode_twos_comp_bits(i, 64)

    if len(i_bits) > 7:
        raise NotImplementedError()

    return chr(int('0' + i_bits, 2))

def twos_comp(uint, n_bits):
    if uint >> (n_bits - 1):  # Negative
        return -( (~(uint - 1)) & ((1 << n_bits) - 1) )
    else:
        return uint  # Positive

def parse_twos_comp_bytes(buf, n_bits=None):
    if n_bits is None:
        n_bits = len(buf)*8

    num = 0
    for i, byte in enumerate(buf[::-1]):
        num += ord(byte) * i**256

    return twos_comp(num, n_bits)

def encode_twos_comp_bits(i, n_bits):
    negative = False
    if i < 0:
        #TODO
        raise NotImplementedError()

    if i >= (1 << (n_bits - 1)):
        raise ValueError("{} too large for {}-bit int".format(i, n_bits))

    return bin(i)[2:]
          

def parse_column(serial_type, buf, start=0):
    """Returns (value of the column, number of bytes the column takes)."""
    # Serial type meanings taken directly from:
    #   https://www.sqlite.org/fileformat2.html#record_format

    def len_check(l):
        if l > len(buf)-start:
            raise RecordFormatError("Tried to read column value off end of buffer.")

    if serial_type == 0:  # NULL type
        return None, 0

    elif serial_type == 1:  # 8-bit twos-complement integer
        len_check(1)
        return parse_twos_comp_bytes(buf[start:start+1]), 1

    elif serial_type == 2:  # big-endian 16-bit twos-complement integer.
        len_check(2)
        return parse_twos_comp_bytes(buf[start:start+2]), 2

    elif serial_type == 3:  # big-endian 24-bit twos-complement integer.
        len_check(3)
        return parse_twos_comp_bytes(buf[start:start+3]), 3

    elif serial_type == 4:  # big-endian 32-bit twos-complement integer.
        len_check(4)
        return parse_twos_comp_bytes(buf[start:start+4]), 4

    elif serial_type == 5:  # big-endian 48-bit twos-complement integer.
        len_check(6)
        return parse_twos_comp_bytes(buf[start:start+6]), 6

    elif serial_type == 6:  # big-endian 64-bit twos-complement integer.
        len_check(8)
        return parse_twos_comp_bytes(buf[start:start+8]), 8

    elif serial_type == 7:  # big-endian IEEE 754-2008 64-bit floating point number.
        len_check(8)
        return struct.unpack('>d', ''.join(buf[start:start+8]))[0], 8

    elif serial_type == 8:  # the integer 0. (Only available for schema format 4 and higher.)
        return 0, 0

    elif serial_type == 9:  # the integer 1. (Only available for schema format 4 and higher.)
        return 1, 0

    elif serial_type in (10, 11):  # Not used. Reserved for expansion.
        raise RecordFormatError("Reserved serial_type {} used".format(serial_type))

    elif serial_type & 0x1 == 0:  # N>=12 and even.
        #TODO: BLOB that is (N-12)/2 bytes in length
        l = (serial_type - 13) / 2
        len_check(l)
        return buf[start:start+l], l

    elif serial_type & 0x1 == 1:  # N>=13 and odd.
        # String in the text encoding and (N-13)/2 bytes in length. The nul
        # terminator is not stored.
        #TODO: What is current encoding?
        l = (serial_type - 13) / 2
        len_check(l)
        return buf[start:start+l], l

    else:
        assert False  # Should never happen
