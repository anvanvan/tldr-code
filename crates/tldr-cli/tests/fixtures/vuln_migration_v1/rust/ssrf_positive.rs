pub fn handler() {
    let u = std::env::var("U").unwrap();
    reqwest::blocking::get(&u).unwrap();
}
