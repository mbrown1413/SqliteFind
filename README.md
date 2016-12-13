
SqliteFind is a Volatility plugin for finding sqlite database rows.

Written by Michael Brown as a project for the Computer Forensics class taught
by Fabian Monrose at the University of North Carolina Chapel Hill. The idea of
searching for sqlite database rows in memory is based on Dave Lassalle's
(@superponible) [firefox volatility
plugins](https://github.com/superponible/volatility-plugins).

Installing
==========

"sqlitefind.py" must be in the plugin path and "sqlitetools.py" must be
importable. You should either add this directory to your volatility plugin
path, or add a link to these files inside the volatility plugin folder.

Requirements:

  * YARA Python API - Running "import yara" should work in Python.

Basic Usage
===========

`-h` or `--help` shows all options.

sqlitefindtables
----------------

The `sqlitefindtables` command looks for every database table in memory and
shows the schema. It outputs a string that can be used directly by `sqlitefind`
to define the column types.

    $ volatility --profile=<profile> -f <memory file> sqlitefindtables


sqlitefind
----------

In the simplest case, the `sqlitefind` volatility command can be invoked without
arguments. This searches every valid address for a valid row. This is very slow
in practice, so generally the expected column types are given using "-c", which
allows us to search more efficiently:

    $ volatility --profile=<profile> -f <memory file> sqlitefind \
                 -c "int,null; int,string; bool"

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

    $ volatility --profile=<profile> -f <memory file> sqlitefind \
                 -c "int,null; string; bool" \
                 -O "address,all_values"

If you try the above, the field names will be something like "Col1", "Col2",
"Col3". You can specify your own names by putting "<name>:" before the types
specified in "-c":

    $ volatility --profile=<profile> -f <memory file> sqlitefind \
                 -c "id:int,null; col1:int,string; col2:bool"

CSV output is also supported, using "--output=csv":

    $ volatility --profile=<profile> -f <memory file> sqlitefind \
                 -c "id:int,null; field1:string; field2:bool" \
                 -O "address,values" \
                 --output=csv --output-file=cookies.csv


Limitations
===========

Needle Size - Based on the table schema, we may not be able to find a suitable
sequence of bytes to search for. The smaller the needle size, the slower the
search will take. Needle sizes of 1 usually don't work, because YARA limits the
number of matches we can find in a block.

Large Records - If a record does not fit in one B-Tree cell, it will be either
missed or corrupted. This is because the rows are searched without using any
database header information. If a row is large enough to be split between
multiple pages, we can only find the data from the first page. After that,
we will either read garbage data, or encounter an error and assume that it's
not a real row.

False positives - There are a lot of checks to make the data parsed is actually
a row, but especially when there are not many columns, false positives can be
found. Usually false positives are easy to recognize by hand. They typically
contain many NULL values (None) and strings will contain nonsensical data.


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

For details on database format, see: [SQLite Database File
Format](https://www.sqlite.org/fileformat2.html)

Each row in an sqlite database looks like this:

    Payload Length (varint)
    Row ID (varint)
    Header:
        Header Length (varint)
        Field 1 Serial Type (varint)
        Field 2 Serial Type (varint)
        ...
    Field 1 (size determined by corresponding type in header)
    Field 2 (size determined by corresponding type in header)
    ...

The varint format is extensively used, which takes up 1 to 9 bytes and
represents a 64-bit twos-compliment integer. The exact encoding is not
important, you just need to know that varint encodes both its own length and an
integer.

The header defines how big each of the fields are by a number called the
[Serial Type](https://www.sqlite.org/fileformat2.html#record_format). The
fields follow immediately afterward. Some of the fields could be zero length
too, like the Serial Types 0x08 and 0x09, which just mean the value is 0 or 1.

The idea for building our needle is to search for the header based on prior
information about the types the fields might have. There is one caveat to this:
string and blob types can take up more than one byte in the header. Because the
varint that stores strings and blobs also encode a length, they can take 1-9
bytes. To get around this, we just search for the largest part of the header
that has a fixed length. For example:

    bool;      null,float;  string;     bool
    (08 | 09)  (00 | 07)    var length  (08 | 09)

The needle would be "(08 | 09)  (00 | 07)", because it's the longest part of the
header that has fixed length. That means "either the byte 0x08 or 0x09,
followed by either the byte 0x00 or 0x07".

The routine that builds the needle also returns where the needle is relative to
the beginning of the record. i.e. it specifies how many varints to count
forwards or backwards and how many bytes to count forwards or backwards to get
to the record. This is what allows the needle to be anywhere in the header. In
the future it will be possible to have a needle located in the beginning of the
actual column data.

Search Memory
-------------

A yara rule is compiled for the needle so searching can be done quickly. The
address space is broken into blocks and yara is called for each. There may be
many matches of our needle that do not actually correspond to a row, but that
is handled in the next step.

Parse Row
---------

Each match is given to the `parse_record` function, which either returns the
data in the row, or raises an error. There are many checks to make sure the
data is actually a row. The types are also checked, since the needle may not
include all columns.

sqlite_master Table
-------------------

The `sqlite_master` table is a special table in sqlite that stores the schemas
for all other tables. The `sql` field stores the sql statement to create the
table. The `sqlitefindtables` command searches for this table, then parses
the sql to get the schema.

The table looks like this:

    CREATE TABLE sqlite_master (
        type TEXT,
        name TEXT,
        tbl_name TEXT,
        rootpage INTEGER,
        sql TEXT
    );

There is a slight problem with searching for this table though: every field
except one is "TEXT"! Since there is only one field that has a fixed length in
the header, our needle size will be 1, making this completely impractical.

Fortunately, there is a better needle. For the kind of entries we're looking
for, the "type" field is always "table". Our needle can just be "table", then
we count backwards over all of the varints in the header to get to the
beginning.
