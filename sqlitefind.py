
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
        yara_rule, header_pos = sqlitetools.get_header_search_pattern(col_type_descriptors)

        searcher = sqlitetools.SqliteRecordSearch(col_type_descriptors)
        for address, types, values in searcher.find_records(address_space):
            yield values

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
