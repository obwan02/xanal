# XANAL
The Xor ANALyser written in rust. This is a small project, mainly intended to be used in simple CTF challenges.

## TODOs (In no particular order)
- [ ] Move test files to test folder (and make proper tests)
- [x] Update Cargo.toml to have correct info, and make sure it is displayed in clap 
- [ ] Maximum key size should be chosen algorithmiclly (i.e. for small input sizes (10-20 chars) max key input should be between 0 and 10) or maybe just a table for small values.
- [ ] Better logging
- [ ] Although crib and search is implemented in `clap` and in rust, need to join them
- [x] Make proper README.md
- [x] Actually make github repo
- [ ] Loading bar for really long files?
- [x] Move key guessing functions outside lib.rs
- [ ] Improve most common byte evaluator
- [ ] Add posibility for multiple different keys to be found
- [ ] Add likelihood of the key found being correct
