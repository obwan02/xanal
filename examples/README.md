# Examples
This directory contains files that have been xor encrypted, and restored by xanal. The encrypted files end with `.enc` and their "cracked" versions enc in `.restored`. This files documents how each file was cracked.

## Test 1
To solve the first example we use known plaintext because there is not much data.
```bash
xanal examples\test1.enc -m 7 crib Congratulations
```
We also need to specify a shorter max key length otherwise xanal will guess the key is very long and will say the crib is too short (this will be fixed in later versions xox). We then give the program a crib and a search term (will be changed in he future to just be a single crib). The output is:
```
Key Length Guess: 5
------------------------------
Key Guess:
Key Guess (base64): ICAgICA=
Key Guess (hex): 0x2020202020
```
The guessed key length is 5, but the key is just the same character repeated, so the actual key length is 1. Therefore the xor key is just `0x20`.

## Test 2
Because there is a lot of data for this test we can just use the most common method:
```bash
xanal examples/test2.enc
```
The output is:
```
Key Length Guess: 9
------------------------------
Key Guess: test_pass
Key Guess (base64): dGVzdF9wYXNz
Key Guess (hex): 0x746573745f70617373
```

## Test 3
This is the same decoded data as test2, just encoded with a single byte instead. The command to decode is:
```
xanal examples/test3.enc
```
The result is:
```
Key Length Guess: 6
------------------------------
Key Guess: qqqqqq
Key Guess (base64): cXFxcXFx
Key Guess (hex): 0x717171717171
```

## Test 4
This is a small sample so known plaintext should be used.
```bash
examples/test4.enc --crib "Hello" --crib-search "test :)" --max-key-length 7
```
The result is:
```
Key Length Guess: 4
------------------------------
Key Guess: beef
Key Guess (base64): YmVlZg==
Key Guess (hex): 0x62656566
```
