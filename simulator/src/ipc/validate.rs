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

//
// You may obtain a copy of the License at
//
//
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//
// You may obtain a copy of the License at
//
//
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use jsonschema::JSONSchema;
use serde_json::Value;

/// Validates JSON input against the simulation-request.schema.json
pub fn validate_request(input: &str) -> Result<Value, String> {
    // include the schema at compile-time
    let schema_json = include_str!("../../../docs/schema/simulation-request.schema.json");
    let schema: Value = serde_json::from_str(schema_json).unwrap();
    let compiled = JSONSchema::compile(&schema).unwrap();

    // parse the incoming JSON
    let instance: Value = serde_json::from_str(input).map_err(|e| e.to_string())?;

    // validate against the schema
    compiled
        .validate(&instance)
        .map_err(|errors| {
            errors
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })?;

    Ok(instance)
}
