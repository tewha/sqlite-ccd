# sqlite-ccd
SQLite functions for various CommonDigest hashes.

To use these, you'll have to build a sqlite3 shell from source as the version of sqlite3 included with macOS X lacks the `.load` command.

After that, you can build the hash library using this command:

    gcc -g -fPIC -dynamiclib hash.c -o hash.dylib

Using your sqlite3 executable, you can load it:

    .load hash.dylib

`hash.dylib` above should be the path to the hash dynamic library, if it's not in the current directory.

Then:

     sqlite> select sha512('');
     cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
    sqlite> select sha512('test');
    ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff

Available hashes:

* md5
* sha256
* sha512

More functions are implemented inside hash.c; to enable them, uncomment the relevant `sqlite3_create_function_v2` lines and rebuild.