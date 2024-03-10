# Tools

This folder contains various tools that can be used in conjunction with sqlelf.

## [docker2sqlelf](./docker2sqlelf)

This script can be given a Docker image name and produce a single sqlite file, using the sqlelf schema, containing
all ELF libraries and binaries found within the image.

```console
$ ./tools/docker2sqlelf debian:stable-20240211
```

A lot of interesting analysis becomes possible when you have a single sqlite file to work with.
You can even attach multiple distributions together and query across them.

```console
$ sqlite3 debian.sqlite
> ATTACH './debian-stable-20240211.sqlite' AS 'debian-stable-20240211';
> ATTACH './debian-stable-20230612.sqlite' AS 'debian-stable-20230612';
> SELECT * FROM pragma_database_list;
seq  name                    file                                                        
---  ----------------------  ------------------------------------------------------------
0    main                    /home/fzakaria/sqlelf/debian.sqlite                                           

2    debian-stable-20240211  /home/sqlelf/debian-stable-20240211.sqlite                           

3    debian-stable-20230612  /home/fzakaria/sqlelf/debian-stable-20230612.sqlite 
```

You can run interesting queries across multiple distributions.

For instance, you can find whether any supported GLIBC version has been added or removed across the two distributions.

```sql
SELECT version
FROM (
    SELECT version, 20230612 AS debian_version FROM `debian-stable-20230612`.elf_symbols
    UNION ALL
    SELECT version, 20240211 AS debian_version FROM `debian-stable-20240211`.elf_symbols
) 
WHERE version LIKE 'GLIBC\_%' ESCAPE '\'
GROUP BY version
HAVING COUNT(DISTINCT debian_version) = 1;
```