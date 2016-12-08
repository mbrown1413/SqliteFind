"""
"""
# Based on Dave Lassalle's (@superponible) firefox volatility plugins:
#     https://github.com/superponible/volatility-plugins

from volatility.scan import BaseScanner
from volatility.commands import Command
from volatility import utils
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
import volatility.debug as debug

import yara

import sqlitetools

class SqliteFind(Command):

    def __init__(self, config, *args, **kwargs):
        super(SqliteFind, self).__init__(config, *args, **kwargs)
        config.add_option('COL-TYPES', short_option='c', default=None,
            help='Descriptor of types each column can have') # TODO: Better help
        config.add_option('OUTPUT-STYLE', short_option='O', default="values",
            help='What fields to include in the output. Comma separated list of any of the values: "all_values" - all of the row\'s values in one field; "values" - Row\'s values in separate fields; "address" - Address of row in memory; "all_types" - List of all serial types in one field.')

    @property
    def col_names(self):
        for name, type_str in self.col_names_and_type_strs:
            yield name

    @property
    def col_type_strs(self):
        for name, type_str in self.col_names_and_type_strs:
            yield type_str

    @property
    def col_names_and_type_strs(self):
        if self._config.COL_TYPES is None:
            return
        else:
            for i, s in enumerate(self._config.COL_TYPES.strip(' ').split(';')):
                if s.count(':') == 0:
                    name = "Col {}".format(i)
                    type_str = s
                elif s.count(':') == 1:
                    name, type_str = s.split(':')
                else:
                    debug.error('Error parsing column types: ":" appeared twice.')

                yield name, type_str

    def calculate(self):
        address_space = utils.load_as(self._config, astype="physical")

        searcher = sqlitetools.SqliteRecordSearch(self.col_type_strs)
        for address, types, values in searcher.find_records(address_space):
            yield address, types, values

    def format_output_fields(self, datum):
        address, types, values = datum
        for field_desc in self._config.OUTPUT_STYLE.split(','):
            if field_desc == "all_values":
                yield str(values)
            elif field_desc == "values":
                for value in values:
                    yield str(value)
            elif field_desc == "address":
                yield Address(address)
            elif field_desc == "all_types":
                yield str(types)

    def get_output_fields(self):
        for field_desc in self._config.OUTPUT_STYLE.split(','):
            if field_desc == "all_values":
                yield "Values", str
            elif field_desc == "values":
                for name in self.col_names:
                    yield name, str
            elif field_desc == "address":
                yield "Address", Address
            elif field_desc == "all_types":
                yield "Types", str
            else:
                debug.error('Unknown field "{}"'.format(field_desc))

    def unified_output(self, data):
        return TreeGrid(
            list(self.get_output_fields()),
            self.generator(data)
        )

    def generator(self, data):
        for datum in data:
            yield (0, list(self.format_output_fields(datum)))
