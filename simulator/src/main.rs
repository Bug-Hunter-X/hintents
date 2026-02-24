// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

mod config;
mod gas_optimizer;
mod runner;
mod source_mapper;
mod types;

use crate::gas_optimizer::{BudgetMetrics, GasOptimizationAdvisor, CPU_LIMIT, MEMORY_LIMIT};
use crate::source_mapper::SourceMapper;
use crate::types::*;
use base64::Engine;
use soroban_env_host::xdr::ReadXdr;
use soroban_env_host::{
    xdr::{HostFunction, Operation, OperationBody, ScVal},
    Host, HostError,
};
use std::env;
use std::io::Read;
use tracing_subscriber::{fmt, EnvFilter};

fn init_logger() {
    // Check if the environment variable ERST_LOG_FORMAT is set to "json"
    let use_json = env::var("ERST_LOG_FORMAT")
        .map(|val| val.to_lowercase() == "json")
        .unwrap_or(false);

    // Default to "info" level logging if not specified
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(std::io::stderr); // Write logs to stderr

    if use_json {
        // Output machine-parsable JSON
        subscriber.json().flatten_event(true).init();
    } else {
        // Output human-readable text
        subscriber.compact().init();
    }
}

fn send_error(msg: String) {
    let res = SimulationResponse {
        status: "error".to_string(),
        error: Some(msg),
        events: vec![],
        diagnostic_events: vec![],
        categorized_events: vec![],
        logs: vec![],
        flamegraph: None,
        optimization_report: None,
        budget_usage: None,
        source_location: None,
    };
    println!("{}", serde_json::to_string(&res).unwrap());
    std::process::exit(1);
}

fn execute_operations(host: &Host, operations: &[Operation]) -> Result<Vec<String>, HostError> {
    let mut logs = Vec::new();
    for op in operations {
        match &op.body {
            OperationBody::InvokeHostFunction(invoke_op) => {
                // In a real simulation we would invoke the host function.
                // host.invoke_function(invoke_op.host_function.clone())?;
                // However, without a full transaction frame setup matching the network,
                // direct invocation might fail or panic if auth is missing.
                // For now, we attempt to invoke but catch errors if possible, or just log.

                // Note: The host provided is already initialized with storage.
                // We really should use `host.invoke_function`.

                logs.push(format!("Executing InvokeHostFunction..."));
                let val = host.invoke_function(invoke_op.host_function.clone())?;
                logs.push(format!("Result: {:?}", val));
            }
            _ => {
                logs.push(format!(
                    "Skipping non-Soroban operation: {:?}",
                    op.body.name()
                ));
            }
        }
    }
    Ok(logs)
}

fn decode_error(msg: &str) -> String {
    if msg.contains("out of bounds memory access") {
        "VM Trap: Out of Bounds Access".to_string()
    } else if msg.contains("unreachable") {
        "VM Trap: Unreachable Instruction".to_string()
    } else if msg.contains("integer divide by zero") {
        "VM Trap: Division by Zero".to_string()
    } else if msg.contains("stack overflow") {
        "VM Trap: Stack Overflow".to_string()
    } else {
        msg.to_string()
    }
}

fn extract_wasm_instruction(topics: &[String], data: &str) -> Option<String> {
    if topics.iter().any(|t| t.contains("budget")) {
        if let Some(pos) = data.find(':') {
            let instr = data[pos + 1..].trim().trim_matches('"').trim_matches(')');
            if !instr.is_empty() {
                return Some(instr.to_string());
            }
        }
    }
    None
}

fn categorize_events(events: &soroban_env_host::events::Events) -> Vec<CategorizedEvent> {
    events
        .0
        .iter()
        .map(|e| {
            let category = match e.event.type_ {
                soroban_env_host::xdr::ContractEventType::Contract => "Contract",
                soroban_env_host::xdr::ContractEventType::System => "System",
                soroban_env_host::xdr::ContractEventType::Diagnostic => "Diagnostic",
            }
            .to_string();

            let contract_id = e.event.contract_id.as_ref().map(|id| format!("{:?}", id));
            let topics = match &e.event.body {
                soroban_env_host::xdr::ContractEventBody::V0(v0) => {
                    v0.topics
                        .iter()
                        .map(|t| format!("{:?}", t))
                        .collect::<Vec<String>>()
                }
            };
            let data = match &e.event.body {
                soroban_env_host::xdr::ContractEventBody::V0(v0) => format!("{:?}", v0.data),
            };

            let wasm_instruction = extract_wasm_instruction(&topics, &data);
            CategorizedEvent {
                category,
                event: DiagnosticEvent {
                    event_type: match e.event.type_ {
                        soroban_env_host::xdr::ContractEventType::Contract => {
                            "contract".to_string()
                        }
                        soroban_env_host::xdr::ContractEventType::System => "system".to_string(),
                        soroban_env_host::xdr::ContractEventType::Diagnostic => {
                            "diagnostic".to_string()
                        }
                    },
                    contract_id,
                    topics,
                    data,
                    in_successful_contract_call: e.failed_call,
                    wasm_instruction,
                },
            }
        })
        .collect()
}

fn main() {
    // 1. Initialize the logger immediately
    init_logger();

    // 2. Log that we started
    tracing::info!(event = "simulator_started", "Simulator initializing...");

    // Read JSON from Stdin
    let mut buffer = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut buffer) {
        let res = SimulationResponse {
            status: "error".to_string(),
            error: Some(format!("Failed to read stdin: {}", e)),
            events: vec![],
            diagnostic_events: vec![],
            categorized_events: vec![],
            logs: vec![],
            flamegraph: None,
            optimization_report: None,
            budget_usage: None,
            source_location: None,
        };
        println!("{}", serde_json::to_string(&res).unwrap());
        eprintln!("Failed to read stdin: {}", e);
        return;
    }

    // Parse Request
    let request: SimulationRequest = match serde_json::from_str(&buffer) {
        Ok(req) => req,
        Err(e) => {
            let res = SimulationResponse {
                status: "error".to_string(),
                error: Some(format!("Invalid JSON: {}", e)),
                events: vec![],
                diagnostic_events: vec![],
                categorized_events: vec![],
                logs: vec![],
                flamegraph: None,
                optimization_report: None,
                budget_usage: None,
                source_location: None,
            };
            println!("{}", serde_json::to_string(&res).unwrap());
            return;
        }
    };

    // Decode Envelope XDR
    let envelope = match base64::engine::general_purpose::STANDARD.decode(&request.envelope_xdr) {
        Ok(bytes) => match soroban_env_host::xdr::TransactionEnvelope::from_xdr(
            bytes,
            soroban_env_host::xdr::Limits::none(),
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

    // Decode ResultMeta XDR
    let _result_meta = if request.result_meta_xdr.is_empty() {
        eprintln!("Warning: ResultMetaXdr is empty. Host storage will be empty.");
        None
    } else {
        match base64::engine::general_purpose::STANDARD.decode(&request.result_meta_xdr) {
            Ok(bytes) => match soroban_env_host::xdr::TransactionResultMeta::from_xdr(
                bytes,
                soroban_env_host::xdr::Limits::none(),
            ) {
                Ok(meta) => Some(meta),
                Err(e) => {
                    return send_error(format!("Failed to parse ResultMeta XDR: {}", e));
                }
            },
            Err(e) => {
                eprintln!("Warning: Failed to decode ResultMeta Base64: {}. Proceeding with empty storage.", e);
                None
            }
        }
    };

    // Initialize source mapper if WASM is provided
    let source_mapper = if let Some(wasm_base64) = &request.contract_wasm {
        match base64::engine::general_purpose::STANDARD.decode(wasm_base64) {
            Ok(wasm_bytes) => {
                let mapper = SourceMapper::new(wasm_bytes);
                if mapper.has_debug_symbols() {
                    eprintln!("Debug symbols found in WASM");
                    Some(mapper)
                } else {
                    eprintln!("No debug symbols found in WASM");
                    None
                }
            }
            Err(e) => {
                eprintln!("Failed to decode WASM base64: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Initialize Host
    let sim_host = runner::SimHost::new(None);
    let host = sim_host.inner;

    let mut loaded_entries_count = 0;

    // Populate Host Storage
    if let Some(entries) = &request.ledger_entries {
        for (key_xdr, entry_xdr) in entries {
            let _key = match base64::engine::general_purpose::STANDARD.decode(key_xdr) {
                Ok(b) => match soroban_env_host::xdr::LedgerKey::from_xdr(
                    b,
                    soroban_env_host::xdr::Limits::none(),
                ) {
                    Ok(k) => k,
                    Err(e) => return send_error(format!("Failed to parse LedgerKey XDR: {}", e)),
                },
                Err(e) => return send_error(format!("Failed to decode LedgerKey Base64: {}", e)),
            };

            let _entry = match base64::engine::general_purpose::STANDARD.decode(entry_xdr) {
                Ok(b) => match soroban_env_host::xdr::LedgerEntry::from_xdr(
                    b,
                    soroban_env_host::xdr::Limits::none(),
                ) {
                    Ok(e) => e,
                    Err(e) => return send_error(format!("Failed to parse LedgerEntry XDR: {}", e)),
                },
                Err(e) => return send_error(format!("Failed to decode LedgerEntry Base64: {}", e)),
            };
            loaded_entries_count += 1;
        }
    }

    // Extract Operations and Simulate
    let operations = match &envelope {
        soroban_env_host::xdr::TransactionEnvelope::Tx(tx_v1) => &tx_v1.tx.operations,
        soroban_env_host::xdr::TransactionEnvelope::TxV0(tx_v0) => &tx_v0.tx.operations,
        soroban_env_host::xdr::TransactionEnvelope::TxFeeBump(bump) => match &bump.tx.inner_tx {
            soroban_env_host::xdr::FeeBumpTransactionInnerTx::Tx(tx_v1) => &tx_v1.tx.operations,
        },
    };

    // Wrap the operation execution in panic protection
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_operations(&host, operations)
    }));

    // Budget and Reporting
    let budget = host.budget_cloned();
    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);

    let cpu_usage_percent = (cpu_insns as f64 / CPU_LIMIT as f64) * 100.0;
    let memory_usage_percent = (mem_bytes as f64 / MEMORY_LIMIT as f64) * 100.0;

    let budget_usage = BudgetUsage {
        cpu_instructions: cpu_insns,
        memory_bytes: mem_bytes,
        operations_count: operations.as_slice().len(),
        cpu_limit: CPU_LIMIT,
        memory_limit: MEMORY_LIMIT,
        cpu_usage_percent,
        memory_usage_percent,
    };

    let optimization_report = if request.enable_optimization_advisor {
        let advisor = GasOptimizationAdvisor::new();
        let metrics = BudgetMetrics {
            cpu_instructions: budget_usage.cpu_instructions,
            memory_bytes: budget_usage.memory_bytes,
            total_operations: budget_usage.operations_count,
        };
        Some(advisor.analyze(&metrics))
    } else {
        None
    };

    let mut flamegraph_svg = None;
    if request.profile.unwrap_or(false) {
        // Simple simulated flamegraph for demonstration
        let folded_data = format!("Total;CPU {}\nTotal;Memory {}\n", cpu_insns, mem_bytes);
        let mut result = Vec::new();
        let mut options = inferno::flamegraph::Options::default();
        options.title = "Soroban Resource Consumption".to_string();

        if let Err(e) =
            inferno::flamegraph::from_reader(&mut options, folded_data.as_bytes(), &mut result)
        {
            eprintln!("Failed to generate flamegraph: {}", e);
        } else {
            flamegraph_svg = Some(String::from_utf8_lossy(&result).to_string());
        }
    }

    match result {
        Ok(Ok(exec_logs)) => {
            // Extract both raw event strings and structured diagnostic events
            let (events, diagnostic_events): (Vec<String>, Vec<DiagnosticEvent>) =
                match host.get_events() {
                    Ok(evs) => {
                        let raw_events: Vec<String> =
                            evs.0.iter().map(|e| format!("{:?}", e)).collect();
                        let diag_events: Vec<DiagnosticEvent> = evs
                            .0
                            .iter()
                            .map(|event| {
                                let event_type = match &event.event.type_ {
                                    soroban_env_host::xdr::ContractEventType::Contract => {
                                        "contract".to_string()
                                    }
                                    soroban_env_host::xdr::ContractEventType::System => {
                                        "system".to_string()
                                    }
                                    soroban_env_host::xdr::ContractEventType::Diagnostic => {
                                        "diagnostic".to_string()
                                    }
                                };

                                let contract_id = event
                                    .event
                                    .contract_id
                                    .as_ref()
                                    .map(|contract_id| format!("{:?}", contract_id));

                                let (topics, data) = match &event.event.body {
                                    soroban_env_host::xdr::ContractEventBody::V0(v0) => {
                                        let topics: Vec<String> =
                                            v0.topics.iter().map(|t| format!("{:?}", t)).collect();
                                        let data = format!("{:?}", v0.data);
                                        (topics, data)
                                    }
                                };

                                let wasm_instruction = extract_wasm_instruction(&topics, &data);
                                DiagnosticEvent {
                                    event_type,
                                    contract_id,
                                    topics,
                                    data,
                                    in_successful_contract_call: event.failed_call,
                                    wasm_instruction,
                                }
                            })
                            .collect();
                        (raw_events, diag_events)
                    }
                    Err(_) => (
                        vec!["Failed to retrieve events".to_string()],
                        Vec::<DiagnosticEvent>::new(),
                    ),
                };

            // Capture categorized events for analyzer
            let categorized_events = match host.get_events() {
                Ok(evs) => categorize_events(&evs),
                Err(_) => vec![],
            };

            let mut final_logs = vec![
                format!("Host Initialized with Budget: {:?}", budget),
                format!("Loaded {} Ledger Entries", loaded_entries_count),
                format!("Captured {} diagnostic events", diagnostic_events.len()),
                format!("CPU Instructions Used: {}", cpu_insns),
                format!("Memory Bytes Used: {}", mem_bytes),
            ];
            for log in exec_logs {
                final_logs.push(log);
            }

            let response = SimulationResponse {
                status: "success".to_string(),
                error: None,
                events,
                diagnostic_events,
                categorized_events,
                logs: final_logs,
                flamegraph: flamegraph_svg,
                optimization_report,
                budget_usage: Some(budget_usage),
                source_location: None,
            };

            println!("{}", serde_json::to_string(&response).unwrap());
        }
        Ok(Err(host_error)) => {
            // Host error during execution (e.g., contract trap, validation failure)
            let error_msg = format!("{:?}", host_error);
            let decoded_msg = decode_error(&error_msg);
            
            let structured_error = StructuredError {
                error_type: "HostError".to_string(),
                message: decoded_msg.clone(),
                details: Some(format!(
                    "Contract execution failed with host error: {}",
                    decoded_msg
                )),
            };

            let response = SimulationResponse {
                status: "error".to_string(),
                error: Some(serde_json::to_string(&structured_error).unwrap()),
                events: vec![],
                diagnostic_events: vec![],
                categorized_events: vec![],
                logs: vec![],
                flamegraph: None,
                optimization_report: None,
                budget_usage: None,
                source_location: None,
            };
            println!("{}", serde_json::to_string(&response).unwrap());
        }
        Err(panic_info) => {
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            let response = SimulationResponse {
                status: "error".to_string(),
                error: Some(format!("Simulator panicked: {}", panic_msg)),
                events: vec![],
                diagnostic_events: vec![],
                categorized_events: vec![],
                logs: vec![format!("PANIC: {}", panic_msg)],
                flamegraph: None,
                optimization_report: None,
                budget_usage: None,
                source_location: None,
            };
            println!("{}", serde_json::to_string(&response).unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_vm_traps() {
        assert!(decode_error("Error: Wasm Trap: out of bounds memory access").contains("VM Trap: Out of Bounds Access"));
        assert!(decode_error("Panic: unreachable").contains("VM Trap: Unreachable Instruction"));
        assert!(decode_error("integer divide by zero").contains("VM Trap: Division by Zero"));
        assert!(decode_error("stack overflow occurred").contains("VM Trap: Stack Overflow"));
        assert_eq!(decode_error("normal error"), "normal error");
    }

    #[test]
    fn test_extract_wasm_instruction() {
        let topics = vec!["budget".to_string(), "tick".to_string()];
        let data = "\"Instruction: i32.add\"".to_string();
        let instr = extract_wasm_instruction(&topics, &data);
        assert_eq!(instr, Some("i32.add".to_string()));

        let data2 = "\"Instruction: call 12\"".to_string();
        let instr2 = extract_wasm_instruction(&topics, &data2);
        assert_eq!(instr2, Some("call 12".to_string()));

        let topics_none = vec!["other".to_string()];
        let instr3 = extract_wasm_instruction(&topics_none, &data);
        assert_eq!(instr3, None);
    }
}
