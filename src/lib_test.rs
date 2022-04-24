
#[test]
fn test_decrypt_1() {
    let encrypted =
        hex::decode(b"2a00090a0d45110e0b16450f11450408421d04080309451207161146584c").unwrap();
    let output: Vec<u8> = super::decrypt(&encrypted, b"beef").collect();
    assert_eq!(&output, b"Hello this is an xanal test :)");
}

#[test]
#[should_panic]
fn test_config_1() {
    let config = super::Config {
        file: String::from("lknfqwefbqiernvkbaxcjhMNZXCLKj.mascl ik.SNFM"),
        crib: None,
        verbose: false,
        target_ic: 0.067,
        crib_offset: None,
        crib_search: None,
        max_key_length: 16,
        no_color_output: true,
        most_common_byte: 0x20,
        key_length_only: false,
        specific_key_length: None,
        output_file: None,
    };

    super::run(config, || ());
}
