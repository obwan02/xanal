# XANAL
The Xor ANALyser written in rust. This is a small project, mainly intended to be used in simple CTF challenges.

## Version 0.1.0 Checklist
- [x] Update Cargo.toml to have correct info, and make sure it is displayed in clap 
- [x] Although crib and search is implemented in `clap` and in rust, need to join them
- [x] Actually make github repo
- [x] Make proper README.md
- [x] Move key guessing functions outside lib.rs

## Version 0.2.0 Checklist
- [ ] Better READEME.md
- [ ] Loading bar for really long files
- [ ] Add posibility for multiple different keys to be found
- [ ] Examples README

## Future Versions (To be announced)
- [ ] Move test files to test folder (and make proper tests)
- [ ] Maximum key size should be chosen algorithmically (i.e. for small input sizes (10-20 chars) max key input should be between 0 and 10) or maybe just a table for small values.
- [ ] Better logging
- [ ] Improve most common byte evaluator
- [ ] Add likelihood of the key found being correct (analyse difference between two known frequencies)

## Version 1.0.0 Checklist
- [ ] Better CLI (maybe have different methods of running as subcommands). For example `xanal common <FILE>` and `xanal crib offset <CRIB> <OFFSET> <FILE>` and `xanal crib search <CRIB> <SEARCH> <FILE>`. May have different method in future the previous commands are just examples.
