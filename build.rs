use vergen::{generate_cargo_keys, ConstantsFlags};
fn main() {
    let mut flags = ConstantsFlags::all();
    flags.remove(ConstantsFlags::SEMVER_FROM_CARGO_PKG);
    generate_cargo_keys(ConstantsFlags::all()).expect("Unable to generate the cargo keys!");
    println!("cargo:rerun-if-changed=resource.rc");
    embed_resource::compile("resource.rc");
}
