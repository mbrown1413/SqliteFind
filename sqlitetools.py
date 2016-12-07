"""
Parsing tools for sqlite records.

These tools are aimed at reading rows from a database file when parts of the
file are missing or corrupted. It does not depend on reading the database
header information, but it it helpful to have prior knowledge about the column
types.

Limitations:

  * If a record does not fit in one B-Tree leaf cell, it will be either missed
    or corrupted.
  * False positives can be found (i.e. data that looks like a row but isn't).

The sqlite format is described here:

    https://www.sqlite.org/fileformat2.html

"""

# Terms used in implementation:
#   type set - A set that describes what possible types of a column. Each item
#              in the set is either a serial type integer or "string" or
#              "blob".

#TODO: Consider using the python bitsting library.

import struct
from collections import namedtuple

import yara  #TODO: Make yara optional
import volatility  #TODO: Make volatility optional


class SqliteParseError(Exception):
    pass


###########################################
########## Parsing And Encoding ###########
###########################################

def parse_record(buf, start=0, n_cols=None, type_sets=None):
    """
    Reads a record in `buf` at position `start`. Return a tuple of serial types
    and a tuple of corresponding values. Many checks are made to validate that
    the data is indeed a record. If any of these checks fail, a
    SqliteParseError is raised.

    `start` should point to the start of the B-Tree leaf cell header that
    contains the record. buf[start] should always be 0x0d.

    If `n_cols` is given, then SqliteParseError is raised if there are not
    that many columns in the record.

    If `type_sets` is given, it should be a list of sets. Each set corresponds
    to a set of possible types for each column, or None if no checks are to be
    made for that column. Values in the set can be an integer serial type (see
    https://www.sqlite.org/fileformat2.html#record_format) or "string" or
    "blob". If `type_sets` is shorter than the number of columns, only the
    first `len(type_sets)` columns are checked for types.
    """
    i = start  # i always points to the next byte in buf to parse

    # B-Tree Leaf Cell Header byte
    if ord(buf[i]) == 0x0d:
        raise SqliteParseError("B-Tree Leaf Cell header 0x0d not present")
    i += 1

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

    # Check: Header length
    if header_len < 2:
        raise SqliteParseError("Header length {} too small".format(header_len))
    if n_cols is not None:
        # Each varint takes 1 to 9 bytes. There is one varint storing the
        # header length, then one for each column.
        max_header_len = 9 * (1 + n_cols)
        min_header_len = 1 * (1 + n_cols)
        if header_len > max_header_len:
            raise SqliteParseError("Header length of {} is too long for {} "
                                   "cols".format(header_len, n_cols))
        if header_len < min_header_len:
            raise SqliteParseError("Header length of {} too short for {} "
                                   "cols".format(header_len, n_cols))

    # Column types
    serial_types = []
    while i < header_start + header_len:
        stype, l = parse_varint(buf, i)
        i += l
        serial_types.append(stype)

    # Check: Record Length
    if i != header_start + header_len:
        raise SqliteParseError("Record header was not the correct length.")

    # Check: n_cols
    if n_cols is not None and len(serial_types) != n_cols:
        raise SqliteParseError("Expected {} columns, got "
                               "{}".format(n_cols, len(serial_types)))

    # Parse columns
    values = []
    for stype in serial_types:
        value, l = parse_col_value(stype, buf, i)
        i += l
        values.append(value)

    # Check: type_sets
    if type_sets is not None:
        for n, (serial_type, type_set) in enumerate(zip(serial_types, type_sets)):
            if type_set is None:
                continue
            if "blob" in type_set and serial_type >= 12 and serial_type & 1 == 0:
                continue
            if "string" in type_set and serial_type >= 13 and serial_type & 1 == 1:
                continue
            if serial_type not in type_set:
                raise SqliteParseError("Serial type for col {} was {}, not "
                        "one of the expected {}".format(n, serial_type,
                                                        type_set))

    # Check: payload length
    # Subtract -3 since payload_len does not include B-Tree Leaf Cell header,
    # payload_len and row_id.
    #TODO: This assumes the varints payload_len and row_id are 1 byte
    actual_payload_len = i - header_start
    if actual_payload_len != payload_len:
        raise SqliteParseError("Payload length field does not match actual "
                               "length of payload. payload_len={}, actual "
                               "length={}".format(payload_len, actual_payload_len))

    return serial_types, values

def count_varints(buf, start=0, n=1, backward=False):
    """Start at `start` in `buf` and return `n` varints forward or backward.

    `start` must point to the first byte of a varint already, or if `backward`
    is True then it must point one byte after a varint ends. Returned is an
    index into `buf` that is `n` varints backwards or forwards from `start`.

    `SqliteParseError` may be raised if the varints are not valid in some way.
    """
    if n < 0:
        n = -n
        backward = not backward

    if not backward: raise NotImplementedError()  #TODO

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
            raise SqliteParseError("Varint ended with 0x80 bit set but was "
                                   "not 9 bytes.")

    return pos

def parse_varint(buf, start=0):
    """Returns (varint integer value, size of varint 1-9)."""
    bits = []
    for i in range(9):
        if start+i >= len(buf):
            raise SqliteParseError("Ran off end of buffer while reading varint")
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
    """Return string of bytes encoding `i` into a varint."""
    varint_bits = []
    i_bits = encode_twos_comp_bits(i, 64)

    if len(i_bits) > 7:
        raise NotImplementedError()  #TODO

    return chr(int('0' + i_bits, 2))

def twos_comp(uint, n_bits):
    if uint >> (n_bits - 1):  # Negative
        return -( (~(uint - 1)) & ((1 << n_bits) - 1) )
    else:
        return uint  # Positive

def parse_twos_comp_bytes(buf, n_bits=None):
    """Return the integer represented in two's compliment in `buf`."""
    if n_bits is None:
        n_bits = len(buf)*8

    num = 0
    for i, byte in enumerate(buf[::-1]):
        num += ord(byte) * i**256

    return twos_comp(num, n_bits)

def encode_twos_comp_bits(i, n_bits):
    """Return the bits in two's compliment format of the signed integer `i`."""
    negative = False
    if i < 0:
        raise NotImplementedError()  #TODO

    if i >= (1 << (n_bits - 1)):
        raise ValueError("{} too large for {}-bit int".format(i, n_bits))

    return bin(i)[2:]

def parse_col_value(serial_type, buf, start=0):
    """Returns (value of the column, number of bytes the column takes)."""
    # Serial type meanings taken directly from:
    #   https://www.sqlite.org/fileformat2.html#record_format

    def len_check(l):
        if l > len(buf)-start:
            raise SqliteParseError("Tried to read column value off end of buffer.")

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
        raise SqliteParseError("Reserved serial_type {} used".format(serial_type))

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


################################
########## Searching ###########
################################

Needle = namedtuple("Needle", "yara_rule varint_offset byte_offset")

class SqliteRecordSearch(object):

    def __init__(self, col_type_strs):
        self.col_type_strs = col_type_strs

        self.type_sets = [_parse_type_str(s) for s in col_type_strs]
        self.needle = _get_search_needle(self.type_sets)

    @property
    def n_cols(self):
        return len(self.type_sets)

    def find_records(self, haystack):
        if isinstance(haystack, volatility.addrspace.BaseAddressSpace):
            return self._find_record_in_address_space(haystack)
        else:
            return self._find_record_in_buf(haystack)

    def _find_record_in_buf(self, buf):
        raise NotImplementedError()  #TODO

    def _find_record_in_address_space(self, address_space):
        for buf, offset, absolute_offset in _search_addr_space(address_space, self.needle.yara_rule):
            try:

                # Count back a number of varints and bytes according to needle
                record_start = count_varints(buf, offset, self.needle.varint_offset) + self.needle.byte_offset

                types, values = parse_record(buf, record_start, self.n_cols, self.type_sets)
                yield absolute_offset, types, values

            except SqliteParseError as e:
                pass  # Match is not an actual record  :(

def _get_search_needle(type_sets):
    can_use_col = lambda c: 'string' not in c and 'blob' not in c
    usable_cols = map(can_use_col, type_sets)
    start, length = _longest_run(usable_cols)

    if start is None:
        raise NotImplementedError("")

    # Build yara hex string
    hex_str = []
    for types in type_sets[start:start+length]:
        hex_str.append('(')

        type_choices = []
        for t in types:
            type_choices.append(hex(t)[2:].zfill(2))
        hex_str.append(' | '.join(type_choices))

        hex_str.append(')')
    hex_str = ' '.join(hex_str)

    rule_str = "rule r1 {{ strings: $a = {{ {} }} condition: $a }}".format(hex_str)
    yara_rule = yara.compile(source=rule_str)

    # Our search puts us `start` varints into the header. There are `start`+3
    # varints (row id, payload length, header length) and one byte (B-Tree leaf
    # cell header byte) to count back until we get to the start of the cell.
    return Needle(yara_rule, -start-3, -1)

def _parse_type_str(type_str):
    """Takes a type string and returns a type set."""
    if len(type_str) == 0:
        raise ValueError('Column type cannot be blank. Use "?" for unknown '
                         'column types.')
    if type_str is '?':
        return None

    type_set = set([])
    for t in type_str.split(','):
        t = t.lower()
        if t == "bool":
            #TODO: Schema format 4 or higher is assumed, make in an option.
            for i in [8, 9]:
                type_set.add(i)
        elif t == "null":
            type_set.add(0)
        elif t == 'int':
            for i in [1, 2, 3, 4, 5, 6, 7, 8, 9]:
                type_set.add(i)
        elif t in ('blob', 'string'):
            type_set.add(t)
        elif t == "notnull":
            type_set.remove(0)
        elif t.startswith('string'):
            raise NotImplementedError()
        elif t == 'timestamp':
            raise NotImplementedError()
        else:
            raise ValueError('Unknown column type "{}"'.format(t))

    return type_set

def _longest_run(xs):
    """
    Return start index and length of the longest run in the list `xs` of items
    that evaluate to True. Return (None, None) if all items are False.
    """
    in_run = False
    run_start = None
    longest_run_len = None
    longest_run_start = None
    for i, x in enumerate(xs):

        if in_run and not x:
            in_run = False
        elif not in_run and x:
            in_run = True
            run_start = i

        if in_run:
            run_len = i - run_start + 1
            if run_len > longest_run_len:
                longest_run_len = run_len
                longest_run_start = run_start

    return longest_run_start, longest_run_len

def _search_addr_space(address_space, rule):
    blocksize = 1024 * 1024 * 10
    overlap = 1024
    match_offsets = set()

    # Iterate over each valid run of memory
    for run_pos, run_size in sorted(address_space.get_available_addresses()):

        # Read in blocks to save memory
        pos = run_pos
        while pos < run_pos+run_size:
            to_read = min(blocksize+overlap, run_pos+run_size - pos)

            # Read and search
            buf = address_space.read(pos, to_read)
            matched_rules = rule.match(data=buf)
            if matched_rules:
                for str_pos, str_name, str_value in matched_rules[0].strings:
                    absolute_offset = str_pos + pos
                    if absolute_offset in match_offsets:
                        continue
                    match_offsets.add(absolute_offset)
                    yield buf, str_pos, absolute_offset

            pos += blocksize
