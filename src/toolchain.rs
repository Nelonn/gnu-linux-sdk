pub fn get_toolchain_content() -> &'static str {
    include_str!("../toolchain.cmake")
}
