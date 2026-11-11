// SPDX-License-Identifier: Apache-2.0
fn main() {
    if verifier::gcp_pregrant_worker::run_stdio().is_err() {
        eprintln!("GCP pre-grant verifier worker failed");
        std::process::exit(1);
    }
}
