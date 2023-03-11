# sqlelf

A tool that utilizes SQLite's virtual table functionality to allow you to explore Linux ELF objects through SQL.

Quick demo showing a _simple SELECT_

```console
❯ sqlelf /usr/bin/ruby /bin/ls
SQLite version 3.40.1 (APSW 3.40.0.0)
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite> .header ON
sqlite> select * from elf_header;
path|type|machine|version|entry
/usr/bin/ruby|3|62|1|4400
/bin/ls|3|62|1|25040
```