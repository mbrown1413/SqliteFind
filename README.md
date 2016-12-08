
SqliteFind is a Volatility plugin for finding sqlite database rows.

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

It is a bit of a pain specifying the full table description using "-c" every
time. Some common tables are predefined, and can be specified with "-P":

    $ volatility --profile=<profile> -f <memory file> sqlitefind -P firefox_cookies

To see a full list of predefined tables, see "--help" or use "-P help".


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


Limitations
===========

Large Records - If a record does not fit in one B-Tree cell, it will be either
missed or corrupted. This is because the rows are searched without using any
database header information. If a row is large enough to be split between
multiple pages, we can only find the data from the first page. After that,
we will either read garbage data, or encounter an error and assume that it's
not a real row.

False positives - There are a lot of checks to make the data parsed is actually
a row, but especially when there are not many columns, false positives can be
found. If no column types are specified, you will definitely see some of these,
but they are usually easy to pick out manually. Hint: include the types in the
output to make falso positives more obvious.


How it Works
============

When you specify the column types using "-c", it searches for a section of the
row header that matches those types. 

  1. Build needle - Based on column types given, figure out what to search for.
  2. Search memory - Finds all instances of needle in memory.
  3. Parse row - Perform checks to make sure this is actually row data. Return
        the data if it looks good.

Build Needle
------------

TODO

Example:

    bool;      null,float;  string;     bool
    (08 | 09)  (00 | 07)    var length  (08 | 09)

The needle would be "(08 | 09)  (00 | 07)", because it's the longest part of the
header that has fixed length.

The routine that builds the needle also returns where the needle is relative to
the beginning of the record. i.e. it specified how many varints to count
forwards or backwards and how many bytes to count forwards or backwards to get
to the record. This is what allows the needle to be anywhere in the header. In
the future it will be possible to have a needle located in the beginning of the
actual column data.

Search Memory
-------------

TODO

Parse Row
---------

TODO
