![xanal - an xor cryptoanalysis tool](img/banner.png)

# XANAL
An Xor cryptoANALyser written in rust. This is a small project, mainly intended to be used in simple CTF challenges. This tool exploits some properties of XOR  It has 3 modes of operation (currently). 

## Version 0.1.0 Checklist
- [x] Update Cargo.toml to have correct info, and make sure it is displayed in clap 
- [x] Although crib and search is implemented in `clap` and in rust, need to join them
- [x] Actually make github repo
- [x] Make proper README.md
- [x] Move key guessing functions outside lib.rs

## Version 0.2.0 Checklist
- [x] Better READEME.md
- [x] Loading bar for really long files
- [x] Add possibility for multiple different keys to be found
- [x] Examples README
- [x] Output multiple files if more than one key is chosen

## Version 0.3.0 Checklist
- [ ] Better logging
- [ ] Implement [key elimination](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Key_elimination) and remove crib and search (which is less effective O(n^2) vs. O(n))
- [ ] Check for repitions in key once it is solved, and reduce size if possible. i.e. "0x202020" => "0x20"

## Version 0.4.0
- [ ] Maximum key size should be chosen algorithmically (i.e. for small input sizes (10-20 chars) max key input should be between 0 and 10) or maybe just a table for small values.
- [ ] Allow for iteration over values that aren't just bytes. For example each utf-8 character can be represented as a number. This would require anlysis of files before hand because if we were to handle utf-8 characters we would need to check that the whole file is utf-8.
- [ ] Change loading bar style
- [ ] Better CLI (maybe have different methods of running as subcommands). For example `xanal common <FILE>` and `xanal crib offset <CRIB> <OFFSET> <FILE>` and `xanal crib search <CRIB> <SEARCH> <FILE>`. May have different method in future the previous commands are just examples.

## Future Versions (To be announced)
- [ ] Move error messages to an other module
- [ ] Move test files to test folder (and make proper tests)
- [ ] Improve most common byte evaluator
- [ ] Add likelihood of the key found being correct (analyse difference between two known frequencies)
- [ ] Examine multiple key length guesses
- [ ] Make every method function through iterators to allow for large file size
- [ ] If we have multiple keys find the one that outputs most plaintext

## Version 1.0.0 Checklist ??
