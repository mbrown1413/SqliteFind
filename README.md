
SqliteFind is a plugin for volatility for finding sqlite database rows.

Installing
==========

"sqlitefind.py" must be in the plugin path and "sqlitetools.py" must be
importable. You should either add this directory to your volatility plugin
path, or link these two files inside the volatility plugin folder.

Requirements:

  * YARA Python API - Running "import yara" should work in Python.

Basic Usage
===========

In the simplest case, the sqlitefind volatility command can be invoked without
arguments. This searches every valid address for a valid row. This is very slow
in practice, so generally the expected column types are given using "-c", which
allows us to search more efficiently:

    $ volatility --profile=<profile> -f <memory file> sqlitefind -c "int,null; int,string; bool"

Each column descriptor is separated by a semicolon (';'). Each descriptor is a
comma (',') separated list of types. You can use the following types:

  * `"?"` - Specifies unknown, could be any type.
  * `"bool"` - Assumes schema format 4 or higher is used. If older schema, use
             "int8".
  * `"null"` - Fields cannot be NULL by default, don't forget to add this if
             needed.
  * `"notnull"` - Negates a previous "null".
  * `"int"`
  * `"int<n bits>"` - `<n bits>` must be one of 8, 16, 24, 32, 48, 64
  * `"float"`
  * `"string" / "blob"`
  * `"string<length>"` / `"blob<length>"` - Like "blob" or "string" but with a
                                       following integer specifying the length.
  * `<serial type>` - A serial type as defined by the [Sqlite file
                    format](https://www.sqlite.org/fileformat2.html#record_format).

One thing to notice is that **NULL is not allowed by default**. Make sure to
add "null" to your type list if it is a possible value.


Predefined Tables
-----------------

TODO


Output Format
=============

You can include different values in the output using the "-O" option, which is
a comma separated list of:

  * `"values"` - A field for each sqlite column.
  * `"all_values"` - One field that is a list of every sqlite column.
  * `"address"` - Address the sqlite row was found in memory.
  * `"all_types"` - A list of types for each column in this row. Each type will
                  be an integer serial type.

For example, to show the memory address of the row followed by the values:

    $ volatility --profile=<profile> -f <memory file> sqlitefind -c "int,null; string; bool" -O "address,all_values"

If you try the above, the field names will be something like "Col1", "Col2",
"Col3". You can specify your own names by putting "<name>:" before the types
specified in "-c":

    $ volatility --profile=<profile> -f <memory file> sqlitefind -c "id:int,null; col1:int,string; col2:bool"

CSV output is also supported, using "--output=csv":

    $ volatility --profile=<profile> -f <memory file> sqlitefind -c "id:int,null; field1:string; field2:bool" -O "address,values" --output=csv --output-file=cookies.csv


How it Works
============

TODO
