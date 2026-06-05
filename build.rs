fn main() {
    println!("cargo:rerun-if-changed=proto/msg.proto");
    println!("cargo:rerun-if-changed=proto/frame.proto");
    prost_build::compile_protos(&["proto/msg.proto", "proto/frame.proto"], &["proto/"])
        .expect("failed to compile protobuf definitions");
}
