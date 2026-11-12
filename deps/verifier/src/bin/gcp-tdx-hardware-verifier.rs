// SPDX-License-Identifier: Apache-2.0
fn main() {
    if verifier::gcp_execution_quote_worker::run_stdio().is_err() {
        eprintln!("GCP hardware verifier worker failed");
        std::process::exit(1);
    }
}
