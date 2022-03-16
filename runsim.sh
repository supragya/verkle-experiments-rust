cargo build --release
rm -r simulation
mkdir simulation
cd simulation && ../target/release/verexp
