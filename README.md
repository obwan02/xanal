# XANAL
The xor analyser written in rust. In early beta

## TODOs
- [ ] Maximum key size should be chosen algorithmiclly (i.e. for small input sizes (10-20 chars) max key input should be between 0 and 10) or maybe just a table for small values.
- [ ] Better logging
- [ ] Although crib and search is implemented in `clap` and in rust, need to join them
- [ ] Make proper README.md
- [ ] Actually make github repo
- [ ] Loading bar for really long files?
- [ ] Move key guessing function outside lib.rs
- [ ] Improve most common byte evaluator
- [ ] Add posibility for multiple different keys to be found
- [ ] Add likelihood of the key found being correct
