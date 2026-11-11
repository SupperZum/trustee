// SPDX-License-Identifier: Apache-2.0

fn main() {
    if verifier::gcp_bootstrap_history_worker::run_stdio().is_err() {
        std::process::exit(1);
    }
}
