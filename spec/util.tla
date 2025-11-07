---------------------------------- MODULE util --------------------------------
(*
 Basic utilities to keep the main spec clean.

 Igor Konnov, 2025
 *)
EXTENDS Integers

Min(a, b) ==
    IF a < b THEN a ELSE b

Max(a, b) ==
    IF a > b THEN a ELSE b

\* Convert options over a subset of keys to a function.
\* @type: (Set(Str), Int, Int, Int) => (Str -> Int);
mk_options(_keys, _blksize, _tsize, _timeout) ==
    [ key \in _keys |->
        IF key = "tsize" THEN _tsize
        ELSE IF key = "blksize" THEN _blksize
        ELSE IF key = "timeout" THEN _timeout
        ELSE 0
    ]

\* Get the value for a key from options, or return a default value.
\* @type: (Str -> Int, Str, Int) => Int;
get_or_else(_options, _key, _default) ==
    IF _key \in DOMAIN _options THEN _options[_key] ELSE _default

===============================================================================