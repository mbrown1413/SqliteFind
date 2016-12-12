"""
"""
# Based on Dave Lassalle's (@superponible) firefox volatility plugins:
#     https://github.com/superponible/volatility-plugins

import csv

from volatility.scan import BaseScanner
from volatility.commands import Command
from volatility import utils
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
import volatility.debug as debug

import yara

import sqlitetools

PREDEFINED_TABLES = {
    "firefox_cookies": "id:int,null; baseDomain:string; originAttributes:string; name:string; value:string; host:string; path:string; expiry:int; lastAccessed:int; creationTime:int; isSecure:bool; isHttpOnly:bool; appId:int; inBrowserElement:bool",
    "sqlite_master": "type:string; name:string; tbl_name:string; rootpage:int; sql:string",
}

class SqliteFind(Command):

    def __init__(self, config, *args, **kwargs):
        super(SqliteFind, self).__init__(config, *args, **kwargs)
        config.add_option('COL-TYPES', short_option='c', default=None,
            help='Descriptor of types each column can have') # TODO: Better help
        config.add_option('OUTPUT-STYLE', short_option='O', default="values",
            help='What fields to include in the output. Comma separated list of any of the values: "all_values" - all of the row\'s values in one field; "values" - Row\'s values in separate fields; "address" - Address of row in memory; "all_types" - List of all serial types in one field; "row_id" - Sqlite rowid that is unique within a table.')
        config.add_option('PREDEFINED-TABLE', short_option="P", default=None,
            choices=PREDEFINED_TABLES.keys(),
            help='Choose column types from a set of predefined tables. Use this instead of "-c" if the table you are searching for is already predefined.')

    def calculate(self):
        address_space = utils.load_as(self._config, astype="physical")

        schema = self.get_schema()
        searcher = sqlitetools.RowSearch(schema)

        print "Needle Size: {}".format(searcher.needle.size)
        if searcher.needle.size < 3:
            print "WARNING: Needle size is small. Things may run slowly."
            print "         If there are too many matches, you will see the error:"
            print '         "yara.Error: internal error: 30"'
        for address, row_id, types, values in searcher.find_records(address_space):
            yield address, row_id, types, values

    def get_schema(self):
        col_type_str = None
        if self._config.COL_TYPES and self._config.PREDEFINED_TABLE:
            debug.error("Cannot use both --col-types (-c) and --predefined-table (-c)")
        if self._config.COL_TYPES is not None:
            col_type_str = self._config.COL_TYPES
        if self._config.PREDEFINED_TABLE is not None:
            col_type_str = PREDEFINED_TABLES[self._config.PREDEFINED_TABLE]

        return sqlitetools.TableSchema.from_str(col_type_str)

    @property
    def col_names(self):
        return self.get_schema().col_names

    def format_output_fields(self, datum):
        address, row_id, types, values = datum
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
            elif field_desc == "row_id":
                yield row_id

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
            elif field_desc == "row_id":
                yield "Row ID", int
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

    def render_csv(self, outfd, data):
        header_row = []
        for field_name, field_type in self.get_output_fields():
            header_row.append(field_name)
        outfd.write(', '.join(header_row))
        outfd.write('\n')

        for d in data:
            fields = list(self.format_output_fields(d))
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(fields)


class SqliteFindTables(Command):

    def __init__(self, config, *args, **kwargs):
        super(SqliteFindTables, self).__init__(config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype="physical")

        needle = sqlitetools.Needle(
            yara.compile(source='rule r1 { strings: $a = "table" condition: $a }'),
            5, -8, 0
        )
        schema = sqlitetools.TableSchema.from_str(PREDEFINED_TABLES["sqlite_master"])
        searcher = sqlitetools.RowSearch(schema, needle)

        for address, row_id, types, values in searcher.find_records(address_space):
            sql = values[4]
            try:
                table_name, table_schema = sqlitetools.TableSchema.from_sql(sql)
            except sqlitetools.SqlParsingError as e:
                continue
            if table_name != values[2]:
                continue
            yield table_name, str(table_schema)

    def unified_output(self, data):
        return TreeGrid([
                ("Name", str),
                ("Column Type String", str),
            ],
            self.generator(data)
        )

    def generator(self, data):
        for name, col_type_str in data:
            yield (0, [str(name), str(col_type_str)])

    def render_csv(self, outfd, data):
        outfd.write('Name, Column Type String\n')
        for row in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(row)
