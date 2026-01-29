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

use serde::Deserialize;
use std::fs;

use super::theme::Theme;
use crate::config::paths::theme_path;

#[derive(Debug, Deserialize)]
struct ThemeConfig {
    span: Option<String>,
    event: Option<String>,
    error: Option<String>,
    warning: Option<String>,
    info: Option<String>,
    dim: Option<String>,
    highlight: Option<String>,
}

pub fn load_theme() -> Theme {
    let default = Theme::default();

    let content = fs::read_to_string(theme_path());
    let Ok(content) = content else {
        return default;
    };

    let Ok(config) = serde_json::from_str::<ThemeConfig>(&content) else {
        return default;
    };

    Theme {
        span: config.span.unwrap_or(default.span),
        event: config.event.unwrap_or(default.event),
        error: config.error.unwrap_or(default.error),
        warning: config.warning.unwrap_or(default.warning),
        info: config.info.unwrap_or(default.info),
        dim: config.dim.unwrap_or(default.dim),
        highlight: config.highlight.unwrap_or(default.highlight),
    }
}
