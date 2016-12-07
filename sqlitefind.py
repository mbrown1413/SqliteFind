
# Based on Dave Lassalle's (@superponible) firefox volatility plugins:
#     https://github.com/superponible/volatility-plugins

#
# https://www.sqlite.org/fileformat2.html#record_format

from volatility.scan import BaseScanner
from volatility.commands import Command
from volatility import utils
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
import volatility.debug as debug

import yara

import sqlitetools


def yara_search_address_space(address_space, rule):
    blocksize = 1024 * 1024 * 10
    overlap = 1024

    # Iterate over each valid run of memory
    for run_pos, run_size in sorted(address_space.get_available_addresses()):

        # Read in blocks to save memory
        pos = run_pos
        while pos < run_pos+run_size:
            to_read = min(blocksize+overlap, run_pos+run_size - pos)

            # Read and search
            #TODO: Remove duplicate matches due to overlapping
            buf = address_space.read(pos, to_read)
            matched_rules = rule.match(data=buf)
            if matched_rules:
                for str_pos, str_name, str_value in matched_rules[0].strings:
                    #import ipdb; ipdb.set_trace()
                    absolute_offset = str_pos + pos
                    yield buf, str_pos, absolute_offset

            pos += blocksize

class Sqlite3Find(Command):

    def __init__(self, config, *args, **kwargs):
        super(Sqlite3Find, self).__init__(config, *args, **kwargs)
        config.add_option('COL-TYPES', short_option='c', default=None,
            help='Descriptor of types each column can have') # TODO: Better help

    def calculate(self):
        if self._config.COL_TYPES is None:
            debug.error("Please give a column type descriptor (-c). For now this is a required argument.")

        address_space = utils.load_as(self._config, astype="physical")
        col_type_descriptors = self._config.COL_TYPES.split(';')
        yara_rule, header_pos = get_header_search_pattern(col_type_descriptors)
        for buf, offset, absolute_offset in yara_search_address_space(address_space, yara_rule):
            try:

                # Count back through varints until we get to the beginning
                # of the record payload. Our search puts us header_pos
                # varints into the header, and there is a row ID and
                # payload length before the header, so we count back
                # header_pos+2 to get to the payload_len field at the
                # beginning of the record.
                # Also count back one byte for the B-Tree Lead Cell header
                record_start = sqlitetools.count_varints(buf, offset, header_pos+3, backward=True) - 1

                types, values = sqlitetools.parse_record(buf, record_start, n_cols=len(col_type_descriptors))
                yield values
                #yield absolute_offset, types, values

            except sqlitetools.SqliteParseError as e:
                pass  # Match is not an actual record  :(

    def unified_output(self, data):
        return TreeGrid(
            [
                #("Offset", Address),
                #("types", str),
                ("values", str),
            ],
            self.generator(data)
        )

    def generator(self, data):
        for values in data:
            yield (0, [
                #Address(offset),
                #str(types),
                str(values),
            ])

def longest_run(xs):
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

def get_header_search_pattern(col_type_descriptors):
    possible_serial_types_by_col = []
    for type_str in col_type_descriptors:
        serial_types = type_str_to_serial_types(type_str)
        possible_serial_types_by_col.append(serial_types)

    viable_cols = map(lambda c: None not in c, possible_serial_types_by_col)
    start, length = longest_run(viable_cols)

    if start is None:
        raise NotImplementedError("")

    # Build yara hex string
    hex_str = []
    for types in possible_serial_types_by_col[start:start+length]:
        hex_str.append('(')

        type_choices = []
        for t in types:
            type_choices.append(hex(t)[2:].zfill(2))
        hex_str.append(' | '.join(type_choices))

        hex_str.append(')')
    hex_str = ' '.join(hex_str)

    rule_str = "rule r1 {{ strings: $a = {{ {} }} condition: $a }}".format(hex_str)
    yara_rule = yara.compile(source=rule_str)

    return yara_rule, start

def type_str_to_serial_types(type_str):
    if type_str is '?':
        return None

    serial_types = set([])
    for t in type_str.split(','):
        t = t.lower()
        if t == "bool":
            #TODO: Schema format 4 or higher is assumed, make in an option.
            for i in [8, 9]:
                serial_types.add(i)
        elif t == "null":
            serial_types.add(0)
        elif t == 'int':
            for i in [1, 2, 3, 4, 5, 6, 7, 8, 9]:
                serial_types.add(i)
        elif t in ('blob', 'str'):
            serial_types.add(None)
        elif t == "notnull":
            serial_types.remove(0)
        elif t.startswith('str'):
            raise NotImplementedError()
        elif t == 'timestamp':
            raise NotImplementedError()
        else:
            debug.error()  #TODO: Error message

    return serial_types
