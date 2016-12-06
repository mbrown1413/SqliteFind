
import sys

import sqlitetools

def main():
    sqlite_file = sys.argv[1]
    buf = open(sqlite_file).read()
    
    for i in range(len(buf)):
        if i not in (2145, ): continue
        values = None
        try:
            serial_types, values = sqlitetools.parse_record(buf, i)
        except sqlitetools.RecordFormatError as e:
            pass
            #print e
        except IndexError as e:
            pass

        if values:
            print i, values

if __name__ == "__main__":
    main()
