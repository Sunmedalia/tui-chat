fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config
        .compile_protos(&["proto/chat.proto"], &["proto"])
        .expect("chat protocol compiles");
    println!("cargo:rerun-if-changed=proto/chat.proto");
}
