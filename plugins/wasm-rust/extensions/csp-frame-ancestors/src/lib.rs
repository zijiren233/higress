// Copyright (c) 2025 Alibaba Group Holding Ltd.
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

use higress_wasm_rust::log::Log;
use higress_wasm_rust::rule_matcher::{on_configure, RuleMatcher, SharedRuleMatcher};
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{ContextType, HeaderAction, LogLevel};
use regex::Regex;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::rc::Rc;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_|Box::new(CSPFrameAncestorsRoot::new()));
}}

const PLUGIN_NAME: &str = "csp-frame-ancestors";
const FRAME_ANCESTORS_KEY: &str = "frame-ancestors";

struct CSPFrameAncestorsRoot {
    log: Log,
    rule_matcher: SharedRuleMatcher<CSPFrameAncestorsConfig>,
}

struct CSPFrameAncestors {
    log: Log,
    rule_matcher: SharedRuleMatcher<CSPFrameAncestorsConfig>,
    csp_matched: bool,
}

fn deserialize_referer_patterns<'de, D>(deserializer: D) -> Result<Vec<Regex>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut ret = Vec::new();
    let value: Value = Deserialize::deserialize(deserializer)?;
    let patterns = value
        .as_array()
        .ok_or_else(|| Error::custom("referer_patterns must be an array"))?;

    if patterns.is_empty() {
        return Err(Error::custom(
            "referer_patterns is required and cannot be empty",
        ));
    }

    for pattern in patterns {
        let pattern_str = pattern
            .as_str()
            .ok_or_else(|| Error::custom("referer_patterns must contain strings"))?;

        if pattern_str.is_empty() {
            continue;
        }

        let regex = Regex::new(pattern_str)
            .map_err(|e| Error::custom(format!("invalid regex pattern '{pattern_str}': {e}")))?;

        ret.push(regex);
    }

    if ret.is_empty() {
        return Err(Error::custom("no valid referer patterns found"));
    }

    Ok(ret)
}

fn deserialize_frame_ancestors<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Value = Deserialize::deserialize(deserializer)?;
    let ancestors = value
        .as_array()
        .ok_or_else(|| Error::custom("frame_ancestors must be an array"))?;

    if ancestors.is_empty() {
        return Err(Error::custom(
            "frame_ancestors is required and cannot be empty",
        ));
    }

    let mut ret = Vec::new();
    for ancestor in ancestors {
        let ancestor_str = ancestor
            .as_str()
            .ok_or_else(|| Error::custom("frame_ancestors must contain strings"))?;

        if !ancestor_str.is_empty() {
            ret.push(ancestor_str.to_string());
        }
    }

    if ret.is_empty() {
        return Err(Error::custom("no valid frame_ancestors found"));
    }

    Ok(ret)
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct CSPFrameAncestorsConfig {
    #[serde(deserialize_with = "deserialize_referer_patterns", default)]
    referer_patterns: Vec<Regex>,
    #[serde(deserialize_with = "deserialize_frame_ancestors", default)]
    frame_ancestors: Vec<String>,
}

impl CSPFrameAncestorsConfig {
    fn space_joined_frame_ancestors(&self) -> String {
        self.frame_ancestors.join(" ")
    }

    fn frame_ancestors_directive(&self) -> String {
        format!("frame-ancestors {}", self.space_joined_frame_ancestors())
    }
}

impl CSPFrameAncestorsRoot {
    fn new() -> Self {
        Self {
            log: Log::new(PLUGIN_NAME.to_string()),
            rule_matcher: Rc::new(RefCell::new(RuleMatcher::default())),
        }
    }
}

impl Context for CSPFrameAncestorsRoot {}

impl RootContext for CSPFrameAncestorsRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        on_configure(
            self,
            plugin_configuration_size,
            self.rule_matcher.borrow_mut().deref_mut(),
            &self.log,
        )
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CSPFrameAncestors {
            log: Log::new(PLUGIN_NAME.to_string()),
            rule_matcher: self.rule_matcher.clone(),
            csp_matched: false,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

impl Context for CSPFrameAncestors {}

impl HttpContext for CSPFrameAncestors {
    fn on_http_request_headers(
        &mut self,
        _num_headers: usize,
        _end_of_stream: bool,
    ) -> HeaderAction {
        let binding = self.rule_matcher.borrow();
        let config = match binding.get_match_config() {
            None => {
                self.log
                    .debug("no matching config found, skipping CSP processing");
                return HeaderAction::Continue;
            }
            Some(config) => config.1,
        };

        // Get the Referer header
        let referer = match self.get_http_request_header("referer") {
            Some(r) if !r.is_empty() => r,
            _ => {
                self.log
                    .debug("no referer header found, skipping CSP processing");
                self.csp_matched = false;
                return HeaderAction::Continue;
            }
        };

        self.log.debug(&format!("checking referer: {referer}"));

        // Check if referer matches any pattern
        let mut matched = false;
        for pattern in &config.referer_patterns {
            if pattern.is_match(&referer) {
                matched = true;
                self.log
                    .debug(&format!("referer matched pattern: {}", pattern.as_str()));
                break;
            }
        }

        self.csp_matched = matched;
        HeaderAction::Continue
    }

    fn on_http_response_headers(
        &mut self,
        _num_headers: usize,
        _end_of_stream: bool,
    ) -> HeaderAction {
        // Check if referer was matched in request phase
        if !self.csp_matched {
            self.log
                .debug("referer not matched, skipping CSP modification");
            return HeaderAction::Continue;
        }

        let binding = self.rule_matcher.borrow();
        let config = match binding.get_match_config() {
            None => {
                return HeaderAction::Continue;
            }
            Some(config) => config.1,
        };

        self.log.debug("referer matched, processing CSP header");

        // Check for X-Frame-Options header and extract allow-from value
        let mut x_frame_options_url = String::new();
        if let Some(x_frame_options) = self.get_http_response_header("x-frame-options") {
            self.log
                .debug(&format!("found X-Frame-Options: {x_frame_options}"));
            x_frame_options_url = extract_allow_from_url(&x_frame_options);
            if !x_frame_options_url.is_empty() {
                self.log
                    .debug(&format!("extracted allow-from URL: {x_frame_options_url}"));
            }
        }

        // Always remove X-Frame-Options header
        // Note: proxy-wasm doesn't have remove_http_response_header, we use set with None
        self.set_http_response_header("x-frame-options", None);
        self.log.debug("removed X-Frame-Options header");

        // Get existing CSP header
        let existing_csp = self.get_http_response_header("content-security-policy");

        let frame_ancestors_directive = config.frame_ancestors_directive();
        self.log.debug(&format!(
            "frame-ancestors directive: {frame_ancestors_directive}"
        ));

        let new_csp = match existing_csp {
            None => {
                // Case 1: No CSP header exists, add new one
                let mut csp = frame_ancestors_directive;
                if !x_frame_options_url.is_empty() {
                    csp.push(' ');
                    csp.push_str(&x_frame_options_url);
                }
                self.log.debug("no existing CSP, adding new header");
                csp
            }
            Some(ref existing) if existing.is_empty() => {
                // Case 1b: Empty CSP header
                let mut csp = frame_ancestors_directive;
                if !x_frame_options_url.is_empty() {
                    csp.push(' ');
                    csp.push_str(&x_frame_options_url);
                }
                self.log.debug("empty CSP, adding new header");
                csp
            }
            Some(ref existing) => {
                // Case 2: CSP header exists, need to process it
                self.log.debug(&format!("existing CSP: {existing}"));
                process_existing_csp(existing, &config, &x_frame_options_url)
            }
        };

        // Set or replace the CSP header
        self.set_http_response_header("content-security-policy", Some(&new_csp));
        self.log.debug(&format!("final CSP: {new_csp}"));

        HeaderAction::Continue
    }
}

// Extract URL from X-Frame-Options allow-from directive
fn extract_allow_from_url(x_frame_options: &str) -> String {
    // Normalize to lowercase for case-insensitive comparison
    let normalized = x_frame_options.trim().to_lowercase();

    // Check if it starts with "allow-from"
    if normalized.starts_with("allow-from") {
        // Extract the URL part after "allow-from"
        let parts: Vec<&str> = x_frame_options.split_whitespace().collect();
        if parts.len() >= 2 {
            let url = parts[1];
            if !url.is_empty() {
                return url.to_string();
            }
        }
    }

    String::new()
}

// Process existing CSP header
fn process_existing_csp(
    existing_csp: &str,
    config: &CSPFrameAncestorsConfig,
    x_frame_options_url: &str,
) -> String {
    // Parse existing CSP into directives
    let mut directives = parse_csp_directives(existing_csp);

    // Check if frame-ancestors directive exists
    let space_joined = config.space_joined_frame_ancestors();

    match directives.get_mut(FRAME_ANCESTORS_KEY) {
        None => {
            // Case 2a: frame-ancestors doesn't exist, append it
            let mut new_directive = space_joined;
            if !x_frame_options_url.is_empty() {
                new_directive.push(' ');
                new_directive.push_str(x_frame_options_url);
            }

            let trimmed = existing_csp.trim_end();
            if trimmed.ends_with(';') {
                format!("{} frame-ancestors {}", existing_csp.trim(), new_directive)
            } else {
                format!("{}; frame-ancestors {}", existing_csp.trim(), new_directive)
            }
        }
        Some(existing_frame_ancestors) => {
            // Case 2b: frame-ancestors exists
            if existing_frame_ancestors == "'none'" || existing_frame_ancestors == "none" {
                // Replace 'none' with configured values
                let mut new_directive = space_joined;
                if !x_frame_options_url.is_empty() {
                    new_directive.push(' ');
                    new_directive.push_str(x_frame_options_url);
                }
                *existing_frame_ancestors = new_directive;
            } else {
                // Append to existing frame-ancestors
                existing_frame_ancestors.push(' ');
                existing_frame_ancestors.push_str(&space_joined);
                if !x_frame_options_url.is_empty() {
                    existing_frame_ancestors.push(' ');
                    existing_frame_ancestors.push_str(x_frame_options_url);
                }
            }

            // Rebuild CSP string
            rebuild_csp(&directives)
        }
    }
}

// Parse CSP directives into a map
fn parse_csp_directives(csp: &str) -> HashMap<String, String> {
    let mut directives = HashMap::new();

    // Split by semicolon
    for part in csp.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Split directive name and values
        if let Some(space_idx) = part.find(' ') {
            let directive_name = part[..space_idx].trim().to_lowercase();
            let directive_value = part[space_idx + 1..].trim().to_string();
            directives.insert(directive_name, directive_value);
        } else {
            // Directive without value
            directives.insert(part.to_lowercase(), String::new());
        }
    }

    directives
}

// Rebuild CSP string from a map of directives
fn rebuild_csp(directives: &HashMap<String, String>) -> String {
    let mut parts = Vec::new();

    // Maintain order: frame-ancestors first, then others
    if let Some(frame_ancestors) = directives.get(FRAME_ANCESTORS_KEY) {
        if !frame_ancestors.is_empty() {
            parts.push(format!("frame-ancestors {frame_ancestors}"));
        }
    }

    // Add remaining directives
    for (name, value) in directives {
        if name == FRAME_ANCESTORS_KEY {
            continue;
        }
        if value.is_empty() {
            parts.push(name.clone());
        } else {
            parts.push(format!("{name} {value}"));
        }
    }

    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_allow_from_url() {
        // Test with valid allow-from
        assert_eq!(
            extract_allow_from_url("ALLOW-FROM https://example.com"),
            "https://example.com"
        );

        // Test with lowercase
        assert_eq!(
            extract_allow_from_url("allow-from https://example.com"),
            "https://example.com"
        );

        // Test with extra spaces
        assert_eq!(
            extract_allow_from_url("  allow-from   https://example.com  "),
            "https://example.com"
        );

        // Test without allow-from
        assert_eq!(extract_allow_from_url("DENY"), "");
        assert_eq!(extract_allow_from_url("SAMEORIGIN"), "");

        // Test empty string
        assert_eq!(extract_allow_from_url(""), "");
    }

    #[test]
    fn test_parse_csp_directives() {
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors https://example.com";
        let directives = parse_csp_directives(csp);

        assert_eq!(directives.get("default-src"), Some(&"'self'".to_string()));
        assert_eq!(
            directives.get("script-src"),
            Some(&"'self' 'unsafe-inline'".to_string())
        );
        assert_eq!(
            directives.get("frame-ancestors"),
            Some(&"https://example.com".to_string())
        );
    }

    #[test]
    fn test_parse_csp_directives_with_empty() {
        let csp = "default-src 'self';;  ; script-src 'self'";
        let directives = parse_csp_directives(csp);

        assert_eq!(directives.len(), 2);
        assert_eq!(directives.get("default-src"), Some(&"'self'".to_string()));
        assert_eq!(directives.get("script-src"), Some(&"'self'".to_string()));
    }

    #[test]
    fn test_rebuild_csp() {
        let mut directives = HashMap::new();
        directives.insert("default-src".to_string(), "'self'".to_string());
        directives.insert(
            "script-src".to_string(),
            "'self' 'unsafe-inline'".to_string(),
        );
        directives.insert(
            "frame-ancestors".to_string(),
            "https://example.com".to_string(),
        );

        let csp = rebuild_csp(&directives);

        // frame-ancestors should be first
        assert!(csp.starts_with("frame-ancestors https://example.com"));
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self' 'unsafe-inline'"));
    }

    #[test]
    fn test_rebuild_csp_without_frame_ancestors() {
        let mut directives = HashMap::new();
        directives.insert("default-src".to_string(), "'self'".to_string());
        directives.insert("script-src".to_string(), "'self'".to_string());

        let csp = rebuild_csp(&directives);

        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("frame-ancestors"));
    }

    #[test]
    fn test_process_existing_csp_no_frame_ancestors() {
        let config = CSPFrameAncestorsConfig {
            referer_patterns: vec![],
            frame_ancestors: vec!["https://example.com".to_string()],
        };

        let existing_csp = "default-src 'self'; script-src 'self'";
        let result = process_existing_csp(existing_csp, &config, "");

        assert!(result.contains("frame-ancestors https://example.com"));
        assert!(result.contains("default-src 'self'"));
        assert!(result.contains("script-src 'self'"));
    }

    #[test]
    fn test_process_existing_csp_with_none() {
        let config = CSPFrameAncestorsConfig {
            referer_patterns: vec![],
            frame_ancestors: vec![
                "https://example.com".to_string(),
                "https://trusted.com".to_string(),
            ],
        };

        let existing_csp = "default-src 'self'; frame-ancestors 'none'";
        let result = process_existing_csp(existing_csp, &config, "");

        assert!(result.contains("frame-ancestors https://example.com https://trusted.com"));
        assert!(!result.contains("'none'"));
        assert!(result.contains("default-src 'self'"));
    }

    #[test]
    fn test_process_existing_csp_append() {
        let config = CSPFrameAncestorsConfig {
            referer_patterns: vec![],
            frame_ancestors: vec!["https://new.com".to_string()],
        };

        let existing_csp = "default-src 'self'; frame-ancestors https://old.com";
        let result = process_existing_csp(existing_csp, &config, "");

        assert!(result.contains("frame-ancestors https://old.com https://new.com"));
        assert!(result.contains("default-src 'self'"));
    }

    #[test]
    fn test_process_existing_csp_with_x_frame_options_url() {
        let config = CSPFrameAncestorsConfig {
            referer_patterns: vec![],
            frame_ancestors: vec!["https://example.com".to_string()],
        };

        let existing_csp = "default-src 'self'";
        let result = process_existing_csp(existing_csp, &config, "https://partner.com");

        assert!(result.contains("frame-ancestors https://example.com https://partner.com"));
        assert!(result.contains("default-src 'self'"));
    }
}
