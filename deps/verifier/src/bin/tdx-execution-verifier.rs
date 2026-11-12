// SPDX-License-Identifier: Apache-2.0

fn main() {
    if verifier::execution_quote_worker::run_stdio().is_err() {
        eprintln!("TDX execution verifier worker failed");
        std::process::exit(1);
    }
}
