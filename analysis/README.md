
Data files are in the `data/` directory. The large files like memory dumps and
databases are not in the repository, but they are available upon request.

Memory dumps were accomplished using virsh dump:

    # virsh dump --domain <machine name> --memory-only --file <name>.img

Fresh Boot
==========

An Ubuntu12.04 VM was booted to the GUI and then a memory snapshot was taken to
see what we find without explicitly opening a database.  See
`data/fresh_boot.img`.

Interestingly, we can find an sqlite database in memory after startup:

    $ volatility --profile=LinuxUbuntu16045x64 \
                 -f data/fresh_boot.img sqlitefindtables
    Name           Column Type String
    uri            id:null,int; value:string,null
    interpretation id:null,int; value:string,null
    manifestation  id:null,int; value:string,null
    payload        id:null,int; value:blob,null
    storage        id:null,int; value:string,null; state:null,int;
                   icon:string,null; display_name:string,null
    text           id:null,int; value:string,null
    mimetype       id:null,int; value:string,null
    actor          id:null,int; value:string,null
    schema_version schema:string,null; version:null,int
    mappings       timestamp:null,int; device:string,null; profile:string,null
    properties     device_id:string,null; property:string,null; value:string,null
    devices        device_id:string,null; device:string,null

The database might have something to do with the GUI, or another service that
runs on startup. To find out, you could print the offsets in memory that the
table schemas were found, then map that back to a process.

There's currently a limitation that keeps us from searching for these rows
though. Every one of them has a needle size of one byte, which would take a
long time to search. YARA raises an error if we have more than 1000000 matches
in one search, and currently the searching is done in blocks of 10 kilobytes.
This can result in too many matches with small needles.  More work is needed to
make searching for small needles work.


Test Database
=============

Gathering Data
--------------

  1. Create database `test_db.sqlite` using `create_test_db.py` script.
  2. Reboot Ubuntu VM.
  3. Open `test_db.sqlite` with the `sqlite3` command.
  4. Execute "SELECT * FROM TESTTABLE;".
  5. Take memory snapshot.

Data files:

  * `testdb_snapshot.img` - Memory snapshot
  * `test_db.sqlite` - Database file

Analysis
--------

Files generated:

  * `recovered_testtable.csv`

The `sqlitefindtables` command correctly finds the schema for the table "testtable":

    $ volatility --profile=LinuxUbuntu16045x64
                 -f data/testdb_snapshot.img sqlitefindtables
    Name           Column Type String
    ...
    testtable      id:null,int; i:int; even:bool,null; odd:bool,null; s:string,null
    ...

Entering the schema into the `sqlitefind` command we can recover the rows:

    $ volatility --profile=LinuxUbuntu16045x64 \
                 -f data/testdb_snapshot.img sqlitefind \
                 -c "id:null,int; i:int; even:bool,null; odd:bool,null; s:string,null" \
                 --output=csv --output-file=data/recovered_testtable.csv
    Outputting to: data/recovered_testtable.csv
    Needle Size: 4

How many of the rows did we recover?

    $ wc -l data/recovered_testtable.csv
    1048

Subtracting out the CSV header, we found 1047 rows. Our database has 1000 rows
in it, so how many actually look like data we inserted?

    $ grep "This is testtable row" data/recovered_testtable.csv | wc -l
    1001

That's strange, we found an extra row! The culprit is one spurious row that
ends with garbage data (here, the syntax `\0xaa` means the byte `0xaa`):

    "347","347","0","1","This is testtable row 3\0xc3\0x97\0xc3\0xbf"

What about things that don't look like our data:

    $ grep -v "This is testtable row" data/recovered_testtable.csv | wc -l
    47

Most of these are found because there are places in memory that look like a
database row, but are't. NULL is a particularly common value because the serial
type for NULL is 0x00. There could also be a table in memory with a similar
schema that we find. In a table with few columns like this, spurious matches
are also more likely. In any case, these spurious matches usually don't look
like interesting data to a human.

Final result:

  * 1047 Rows found
  * 1000 / 1000 True positives found
  * 47 False Positives


Firefox Places Database
=======================

Gathering Data
--------------

  1. Reboot Ubuntu VM.
  2. Open firefox and go to "example.com".
  3. Take memory snapshot.
  4. Copy `places.sqlite` in the firefox profile directory.

Data files:
  * `firefox.img` - Memory snapshot
  * `firefox_places.sqlite` - Places database

Analysis
--------

When firefox is running, there are many more tables in memory (ones present at
fresh boot were subtracted from this output):

    $ ~/install/volatility/vol.py --profile=LinuxUbuntu16045x64
                                  -f analysis/data/firefox.img sqlitefindtables
    Name                    Column Type String
    ...
    moz_downloads           id:int,null; name:string,null; source:string,null;
                            target:string,null; tempPath:string,...
    moz_deleted_logins      id:int,null; guid:string,null; timeDeleted:int,null
    moz_disabledHosts       id:int,null; hostname:string,null
    moz_logins              id:int,null; hostname:string; httpRealm:string,null;
                            formSubmitURL:string,null; usernam...
    moz_keywords            id:int,null; keyword:string,null
    moz_bookmarks           id:int,null; type:int,null; fk:int,null; parent:int,null;
                            position:int,null; title:stri...
    moz_hosts               id:int,null; host:string; frecency:int,null;
                            typed:int; prefix:string,null
    moz_historyvisits       id:int,null; from_visit:int,null; place_id:int,null;
                            visit_date:int,null; visit_type:int,null; session:int,null
    moz_places              id:int,null; url:string,null; title:string,null;
                            rev_host:string,null; visit_count:int,...
    expiration_notify       id:int,null; v_id:int,null; p_id:int,null;
                            url:string; guid:string; visit_date:int,null;...
    prefs                   id:int,null; groupID:int,null; settingID:int; value:blob,null
    settings                id:int,null; name:string
    groups                  id:int,null; name:string
    webappsstore2           scope:string,null; key:string,null; value:string,null;
                            secure:int,null; owner:string,null
    moz_deleted_formhistory id:int,null; timeDeleted:int,null; guid:string,null
    moz_formhistory         id:int,null; fieldname:string; value:string;
                            timesUsed:int,null; firstUsed:int,null; lastUsed:int,null;...
    moz_openpages_temp      url:string,null; open_count:int,null
    moz_hosts               id:int,null; host:string,null; type:string,null;
                            permission:int,null; expireType:int,null; expireTime:int,null;
                            appId:int,null; isInBrowserElement:int,null

See `data/firefox_tables.csv` for a complete list without the type string
truncated.

We'll see if we can recover the `moz_places` table:

    $ volatility --profile=LinuxUbuntu16045x64 -f data/firefox.img sqlitefind \
                 --output=csv --output-file data/firefox_recovered_places.csv
                 -c "id:null,int; url:string,null; title:string,null; \
                     rev_host:string,null; visit_count:null,int; hidden:int; \
                     typed:int; favicon_id:null,int; frecency:int; \
                     last_visit_date:null,int; guid:string,null"
    Outputting to: analysis/data/firefox_recovered_places.csv
    Needle Size: 6

You can look at the data yourself in `data/firefox_recovered_places.csv` and
`data/firefox_places.sqlite`. There are a few things that are a bit off about
the data recovered.

First of all, the "id" fields are all NULL, even though the original sqlite
file has data for every "id" field. As it turns out, because "id" is a PRIMARY
KEY field, sqlite uses the rowid for the value. This makes sense, because rowid
is guarenteed to be unique anyways. You can include rowid in the output using
the "--output-cols" option, and indeed, the rowid is always equal to the
primary key id value.

The values of the "frecency" field are all a bit different between our memory
image and the database file. This field is a sort of score of importance for
the site that changes over time (how long since the user has visited the site).
I think it's likely that firefox changed these values between the memory
capture and when I copied the sqlite files off of the VM.

There are actually extra rows we recovered that weren't in the original
database:

    "None","http://example.com/","Example Domain","moc.elpmaxe.","1",
        "0","1","None","2000","1471970854178187","_Fv9IX1cGpN4"

    "None","http://example.com/","Example Domain","moc.elpmaxe.","2",
        "0","1","None","2000","1481564460988099","_Fv9IX1cGpN4"

    "None","https://news.ycombinator.com/","Hacker News","moc.rotanibmocy.swen.","1",
        "0","0","11","2000","1471970845483557","-yx4LJ_n$D"

    "None","http://www.mozilla.z\0x13\0xc3\0xa9\0xc3\0xac","None",
        "\0xc3\0xbb#\0xc2\0xbbK\0x2g...","0","0","0","None","-26731","None",""

The last one is obviously junk, since the strings have nonprintable characters
in them. I suspect that this is an old row that was updated or deleted, but
never had the actual bits storing it cleared. The other rows could be the same
kind of artifact, but more research is needed to tell for sure. The first two
actually have the same "guid", but different "last_visit_date" values. The
third has a "guid" that is similar to another row in the table.
