// Copyright (c) 2026 dotandev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use soroban_env_host::xdr::ReadXdr;
use std::collections::HashMap;
use std::io::{self, Read};

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SimulationRequest {
    envelope_xdr: String,
    result_meta_xdr: String,
    // Key XDR -> Entry XDR
    ledger_entries: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct SimulationResponse {
    status: String,
    error: Option<String>,
    events: Vec<String>,
    logs: Vec<String>,
}

// -----------------------------------------------------------------------------
// Main Execution
// -----------------------------------------------------------------------------

fn main() {
    // Read JSON from Stdin
    let mut buffer = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buffer) {
        eprintln!("Failed to read stdin: {}", e);
        return;
    }

    // Parse Request
    let request: SimulationRequest = match serde_json::from_str(&buffer) {
        Ok(req) => req,
        Err(e) => {
            return send_error(format!("Invalid JSON: {}", e));
        }
    };

    // Decode Envelope XDR
    let envelope = match base64::engine::general_purpose::STANDARD.decode(&request.envelope_xdr) {
        Ok(bytes) => match soroban_env_host::xdr::TransactionEnvelope::from_xdr(
            bytes,
            &soroban_env_host::xdr::Limits::none(),
        ) {
            Ok(env) => env,
            Err(e) => {
                return send_error(format!("Failed to parse Envelope XDR: {}", e));
            }
        },
        Err(e) => {
            return send_error(format!("Failed to decode Envelope Base64: {}", e));
        }
    };

    // Initialize Host
    let host = soroban_env_host::Host::default();
    host.set_diagnostic_level(soroban_env_host::DiagnosticLevel::Debug)
        .unwrap();

    let mut loaded_entries_count = 0;

    // Populate Host Storage
    if let Some(entries) = &request.ledger_entries {
        for (key_xdr, entry_xdr) in entries {
            let _key = match base64::engine::general_purpose::STANDARD.decode(key_xdr) {
                Ok(b) => match soroban_env_host::xdr::LedgerKey::from_xdr(b, &soroban_env_host::xdr::Limits::none()) {
                    Ok(k) => k,
                    Err(e) => return send_error(format!("Failed to parse LedgerKey XDR: {}", e)),
                },
                Err(e) => return send_error(format!("Failed to decode LedgerKey Base64: {}", e)),
            };

            let _entry = match base64::engine::general_purpose::STANDARD.decode(entry_xdr) {
                Ok(b) => match soroban_env_host::xdr::LedgerEntry::from_xdr(b, &soroban_env_host::xdr::Limits::none()) {
                    Ok(e) => e,
                    Err(e) => return send_error(format!("Failed to parse LedgerEntry XDR: {}", e)),
                },
                Err(e) => return send_error(format!("Failed to decode LedgerEntry Base64: {}", e)),
            };
            loaded_entries_count += 1;
        }
    }

    let mut invocation_logs = vec![];

    // Extract Operations and Simulate
    let operations = match &envelope {
        soroban_env_host::xdr::TransactionEnvelope::Tx(tx_v1) => &tx_v1.tx.operations,
        soroban_env_host::xdr::TransactionEnvelope::TxV0(tx_v0) => &tx_v0.tx.operations,
        soroban_env_host::xdr::TransactionEnvelope::TxFeeBump(bump) => match &bump.tx.inner_tx {
            soroban_env_host::xdr::FeeBumpTransactionInnerTx::Tx(tx_v1) => &tx_v1.tx.operations,
        },
    };

    for op in operations.iter() {
        if let soroban_env_host::xdr::OperationBody::InvokeHostFunction(host_fn_op) = &op.body {
            match &host_fn_op.host_function {
                soroban_env_host::xdr::HostFunction::InvokeContract(invoke_args) => {
                    invocation_logs.push(format!("Invoking Contract: {:?}", invoke_args.contract_address));
                    // In a real implementation, host.invoke_function would be called here.
                    // If it returned an Err, we would pass it to decode_error.
                }
                _ => invocation_logs.push("Skipping non-InvokeContract Host Function".to_string()),
            }
        }
    }

    let events = match host.get_events() {
        Ok(evs) => evs.0.iter().map(|e| format!("{:?}", e)).collect::<Vec<String>>(),
        Err(e) => vec![format!("Failed to retrieve events: {:?}", e)],
    };

    // Final Response
    let response = SimulationResponse {
        status: "success".to_string(),
        error: None,
        events,
        logs: {
            let mut logs = vec![
                format!("Host Initialized. Loaded {} Ledger Entries", loaded_entries_count),
            ];
            logs.extend(invocation_logs);
            logs
        },
    };

    println!("{}", serde_json::to_string(&response).unwrap());
}

// -----------------------------------------------------------------------------
// Decoder Logic
// -----------------------------------------------------------------------------

/// Decodes generic errors and WASM traps into human-readable messages.
/// 
/// Differentiates between:
/// 1. VM-initiated traps (WASM execution failures)
/// 2. Host-initiated traps (Soroban environment logic failures)
fn decode_error(err_msg: &str) -> String {
    let err_lower = err_msg.to_lowercase();

    // Check for VM-initiated traps (Pure WASM)
    if err_lower.contains("wasm trap") || err_lower.contains("trapped") {
        if err_lower.contains("unreachable") {
            return "VM Trap: Unreachable Instruction (Panic or invalid code path)".to_string();
        }
        if err_lower.contains("out of bounds") || err_lower.contains("memory access") {
            return "VM Trap: Out of Bounds Access (Invalid memory read/write)".to_string();
        }
        if err_lower.contains("integer overflow") || err_lower.contains("arithmetic overflow") {
            return "VM Trap: Integer Overflow".to_string();
        }
        if err_lower.contains("stack overflow") || err_lower.contains("call stack exhausted") {
            return "VM Trap: Stack Overflow (Recursion limit exceeded)".to_string();
        }
        if err_lower.contains("divide by zero") {
            return "VM Trap: Division by Zero".to_string();
        }
        return format!("VM Trap: Unknown Wasm Trap ({})", err_msg);
    }

    // Check for Host-initiated traps (Soroban Host Logic)
    if err_lower.contains("hosterror") || err_lower.contains("context") {
        return format!("Host Trap: {}", err_msg);
    }

    // Fallback
    format!("Execution Error: {}", err_msg)
}

fn send_error(msg: String) {
    let res = SimulationResponse {
        status: "error".to_string(),
        error: Some(msg),
        events: vec![],
        logs: vec![],
    };
    println!("{}", serde_json::to_string(&res).unwrap());
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_vm_traps() {
        // 1. Out of Bounds
        let msg = decode_error("Error: Wasm Trap: out of bounds memory access");
        assert!(msg.contains("VM Trap: Out of Bounds Access"));

        // 2. Integer Overflow
        let msg = decode_error("Error: trapped: integer overflow");
        assert!(msg.contains("VM Trap: Integer Overflow"));

        // 3. Stack Overflow
        let msg = decode_error("Wasm Trap: call stack exhausted");
        assert!(msg.contains("VM Trap: Stack Overflow"));

        // 4. Unreachable
        let msg = decode_error("Wasm Trap: unreachable");
        assert!(msg.contains("VM Trap: Unreachable Instruction"));
    }

    #[test]
    fn test_decode_host_traps() {
        // Host Error
        let msg = decode_error("HostError: Error(Context, InvalidInput)");
        assert!(msg.contains("Host Trap"));
        assert!(!msg.contains("VM Trap"));
    }

    #[test]
    fn test_unknown_trap_fallback() {
        let msg = decode_error("Wasm Trap: something weird happened");
        assert!(msg.contains("VM Trap: Unknown Wasm Trap"));
    }
}