pub fn handler() {
    let p = std::env::var("P").unwrap();
    std::fs::File::open(&p).unwrap();
}
