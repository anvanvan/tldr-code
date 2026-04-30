pub fn handler() {
    let cmd = std::env::var("CMD").unwrap();
    std::process::Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
}
