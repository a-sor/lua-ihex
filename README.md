# lua-ihex

Don't ask me why someone would implement [Intel HEX](https://en.wikipedia.org/wiki/Intel_HEX)-to-binary conversion in [Lua](https://www.lua.org/) :) But if you need to, you could spare yourself some hassle by using this simple module. It exports two plain functions:

```lua
-- Convert an Intel HEX file into a binary file.
-- Return:
--   true on success,
--   false, "error message" on error.

function ihex_to_bin(ihex_filename, bin_filename)
```

```lua
-- Convert a binary file into an Intel HEX file. The optional address parameter
-- determines the starting address of the data. If omitted, assume 0 as default
-- value.
-- Return:
--   true on success,
--   false, "error message" on error.

function bin_to_ihex(bin_filename, ihex_filename, address)
```

That's all. Unfortunately, I'm not providing any tests or examples yet. I'll fix this some time in the future :)
