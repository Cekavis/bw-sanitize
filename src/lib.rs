mod analysis;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use analysis::{
    AnalysisSummary, AnalyzeOptions, MergeAnalysis, MergeApplyOptions, MergeApplyReport,
    MergeCandidate, PasswordConflict, PasswordVariant, ReportItem, ReviewGroup,
    analysis_to_markdown, analyze_merge_candidates, apply_recommended_merges,
};

const TOKEN_PREFIX: &str = "__BW_MAP_";
const TOKEN_SUFFIX: &str = "__";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingFile {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub entries: BTreeMap<String, String>,
}

impl Default for MappingFile {
    fn default() -> Self {
        Self {
            version: default_version(),
            entries: BTreeMap::new(),
        }
    }
}

fn default_version() -> u8 {
    1
}

#[derive(Debug)]
pub struct SanitizeReport {
    pub replaced_values: usize,
    pub total_mappings: usize,
}

#[derive(Debug)]
pub struct RestoreReport {
    pub restored_values: usize,
}

#[derive(Debug)]
pub struct Sanitizer {
    mapping: MappingFile,
    original_to_token: BTreeMap<String, String>,
    next_index: usize,
    replaced_values: usize,
}

impl Sanitizer {
    pub fn new(mapping: MappingFile) -> Self {
        let mut original_to_token = BTreeMap::new();
        let mut next_index = 1;

        for (token, original) in &mapping.entries {
            original_to_token
                .entry(original.clone())
                .or_insert_with(|| token.clone());

            if let Some(index) = parse_token_index(token) {
                next_index = next_index.max(index + 1);
            }
        }

        Self {
            mapping,
            original_to_token,
            next_index,
            replaced_values: 0,
        }
    }

    pub fn sanitize(mut self, value: &mut Value) -> (MappingFile, SanitizeReport) {
        let mut path = Vec::new();
        self.sanitize_value(value, &mut path);

        let report = SanitizeReport {
            replaced_values: self.replaced_values,
            total_mappings: self.mapping.entries.len(),
        };

        (self.mapping, report)
    }

    fn sanitize_value(&mut self, value: &mut Value, path: &mut Vec<PathSegment>) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    path.push(PathSegment::Key(key.clone()));
                    self.sanitize_value(child, path);
                    path.pop();
                }
            }
            Value::Array(array) => {
                for child in array {
                    path.push(PathSegment::Array);
                    self.sanitize_value(child, path);
                    path.pop();
                }
            }
            Value::String(text) => {
                if should_mask(path, text) {
                    let token = self.token_for(text);
                    *text = token;
                    self.replaced_values += 1;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn token_for(&mut self, original: &str) -> String {
        if let Some(token) = self.original_to_token.get(original) {
            return token.clone();
        }

        let token = loop {
            let candidate = format!("{TOKEN_PREFIX}{:06}{TOKEN_SUFFIX}", self.next_index);
            self.next_index += 1;

            if !self.mapping.entries.contains_key(&candidate) {
                break candidate;
            }
        };

        self.mapping
            .entries
            .insert(token.clone(), original.to_owned());
        self.original_to_token
            .insert(original.to_owned(), token.clone());
        token
    }
}

pub fn sanitize_json(value: &mut Value, mapping: MappingFile) -> (MappingFile, SanitizeReport) {
    Sanitizer::new(mapping).sanitize(value)
}

pub fn restore_json(value: &mut Value, mapping: &MappingFile) -> RestoreReport {
    let restored_values = restore_value(value, &mapping.entries);
    RestoreReport { restored_values }
}

pub fn load_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("failed to serialize JSON")?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

pub fn load_mapping(path: &Path) -> Result<MappingFile> {
    if !path.exists() {
        return Ok(MappingFile::default());
    }

    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;

    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(MappingFile::default());
    }

    let mapping: MappingFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    if mapping.version != 1 {
        anyhow::bail!(
            "unsupported mapping version {} in {}",
            mapping.version,
            path.display()
        );
    }

    Ok(mapping)
}

pub fn write_mapping(path: &Path, mapping: &MappingFile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(mapping).context("failed to serialize mapping")?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSegment {
    Key(String),
    Array,
}

fn restore_value(value: &mut Value, entries: &BTreeMap<String, String>) -> usize {
    match value {
        Value::Object(object) => object
            .values_mut()
            .map(|child| restore_value(child, entries))
            .sum(),
        Value::Array(array) => array
            .iter_mut()
            .map(|child| restore_value(child, entries))
            .sum(),
        Value::String(text) => {
            if let Some(original) = entries.get(text) {
                *text = original.clone();
                1
            } else {
                0
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

fn parse_token_index(token: &str) -> Option<usize> {
    token
        .strip_prefix(TOKEN_PREFIX)?
        .strip_suffix(TOKEN_SUFFIX)?
        .parse()
        .ok()
}

fn should_mask(path: &[PathSegment], text: &str) -> bool {
    if text.is_empty() || should_preserve(path) {
        return false;
    }

    keys(path).first().is_some_and(|root| *root == "items")
}

fn should_preserve(path: &[PathSegment]) -> bool {
    let path_keys = keys(path);

    let Some(last_key) = path_keys.last().copied() else {
        return true;
    };

    if is_metadata_key(last_key) {
        return true;
    }

    matches!(
        path_keys.as_slice(),
        ["folders", "name"]
            | ["items", "name"]
            | ["items", "login", "uris", "uri"]
            | ["items", "card", "number"]
            | ["items", "fields", "name"]
            | ["items", "collectionIds"]
    )
}

fn keys(path: &[PathSegment]) -> Vec<&str> {
    path.iter()
        .filter_map(|segment| match segment {
            PathSegment::Key(key) => Some(key.as_str()),
            PathSegment::Array => None,
        })
        .collect()
}

fn is_metadata_key(key: &str) -> bool {
    matches!(
        key,
        "id" | "organizationId"
            | "folderId"
            | "collectionId"
            | "object"
            | "type"
            | "reprompt"
            | "creationDate"
            | "revisionDate"
            | "deletedDate"
            | "lastUsedDate"
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn masks_repeated_sensitive_values_with_same_token() {
        let mut value = json!({
            "items": [
                {
                    "name": "Bank",
                    "login": {
                        "username": "same-secret",
                        "password": "same-secret",
                        "uris": [{ "uri": "https://example.com" }]
                    },
                    "fields": [
                        { "name": "pin", "value": "same-secret", "type": 1 }
                    ]
                }
            ]
        });

        let (mapping, report) = sanitize_json(&mut value, MappingFile::default());

        assert_eq!(report.replaced_values, 3);
        assert_eq!(mapping.entries.len(), 1);
        assert_eq!(
            value["items"][0]["login"]["username"],
            value["items"][0]["login"]["password"]
        );
        assert_eq!(
            value["items"][0]["login"]["password"],
            value["items"][0]["fields"][0]["value"]
        );
    }

    #[test]
    fn preserves_selected_dedupe_fields() {
        let mut value = json!({
            "folders": [{ "id": "folder-id", "name": "Finance" }],
            "items": [
                {
                    "id": "item-id",
                    "folderId": "folder-id",
                    "name": "Credit card",
                    "revisionDate": "2026-05-20T00:00:00Z",
                    "login": {
                        "username": "private-user",
                        "password": "private-password",
                        "uris": [{ "uri": "https://bank.example" }]
                    },
                    "card": {
                        "cardholderName": "Private Name",
                        "brand": "Visa",
                        "number": "4111111111111111",
                        "expMonth": "01",
                        "expYear": "2030",
                        "code": "123"
                    },
                    "fields": [{ "name": "answer", "value": "secret answer" }]
                }
            ]
        });

        let original = value.clone();
        let (mapping, _) = sanitize_json(&mut value, MappingFile::default());

        assert_eq!(value["folders"][0]["name"], original["folders"][0]["name"]);
        assert_eq!(value["items"][0]["id"], original["items"][0]["id"]);
        assert_eq!(
            value["items"][0]["folderId"],
            original["items"][0]["folderId"]
        );
        assert_eq!(value["items"][0]["name"], original["items"][0]["name"]);
        assert_eq!(
            value["items"][0]["revisionDate"],
            original["items"][0]["revisionDate"]
        );
        assert_eq!(
            value["items"][0]["login"]["uris"][0]["uri"],
            original["items"][0]["login"]["uris"][0]["uri"]
        );
        assert_eq!(
            value["items"][0]["card"]["number"],
            original["items"][0]["card"]["number"]
        );
        assert_eq!(
            value["items"][0]["fields"][0]["name"],
            original["items"][0]["fields"][0]["name"]
        );

        assert_ne!(
            value["items"][0]["login"]["username"],
            original["items"][0]["login"]["username"]
        );
        assert_ne!(
            value["items"][0]["card"]["cardholderName"],
            original["items"][0]["card"]["cardholderName"]
        );
        assert_ne!(
            value["items"][0]["card"]["code"],
            original["items"][0]["card"]["code"]
        );
        assert_eq!(mapping.entries.len(), 8);
    }

    #[test]
    fn masks_secure_notes_identity_passkeys_and_ssh_strings() {
        let mut value = json!({
            "items": [
                {
                    "type": 2,
                    "name": "Secure note",
                    "notes": "private note",
                    "secureNote": { "type": 0 }
                },
                {
                    "type": 4,
                    "name": "Identity",
                    "identity": {
                        "firstName": "Ada",
                        "lastName": "Lovelace",
                        "email": "ada@example.com"
                    }
                },
                {
                    "type": 1,
                    "name": "Login with passkey",
                    "login": {
                        "fido2Credentials": [
                            {
                                "credentialId": "credential",
                                "keyValue": "key",
                                "rpId": "example.com",
                                "userName": "user"
                            }
                        ]
                    }
                },
                {
                    "type": 5,
                    "name": "SSH key",
                    "sshKey": {
                        "privateKey": "private",
                        "publicKey": "public",
                        "fingerprint": "fingerprint"
                    }
                }
            ]
        });

        let original = value.clone();
        let (_, report) = sanitize_json(&mut value, MappingFile::default());

        assert_eq!(report.replaced_values, 11);
        assert_ne!(value["items"][0]["notes"], original["items"][0]["notes"]);
        assert_ne!(
            value["items"][1]["identity"]["email"],
            original["items"][1]["identity"]["email"]
        );
        assert_ne!(
            value["items"][2]["login"]["fido2Credentials"][0]["keyValue"],
            original["items"][2]["login"]["fido2Credentials"][0]["keyValue"]
        );
        assert_ne!(
            value["items"][3]["sshKey"]["privateKey"],
            original["items"][3]["sshKey"]["privateKey"]
        );
    }

    #[test]
    fn restore_round_trips_sanitized_json() {
        let original = json!({
            "folders": [{ "id": "folder-id", "name": "Finance" }],
            "items": [
                {
                    "id": "item-id",
                    "type": 1,
                    "name": "Email",
                    "notes": "private note",
                    "login": {
                        "username": "ada",
                        "password": "password",
                        "totp": "otpauth://totp/secret",
                        "uris": [{ "uri": "https://mail.example" }]
                    },
                    "passwordHistory": [
                        { "lastUsedDate": "2026-05-20T00:00:00Z", "password": "old-password" }
                    ],
                    "fields": [{ "name": "recovery", "value": "blue" }]
                }
            ]
        });

        let mut sanitized = original.clone();
        let (mapping, sanitize_report) = sanitize_json(&mut sanitized, MappingFile::default());

        assert_eq!(sanitize_report.replaced_values, 6);
        assert_ne!(sanitized, original);

        let restore_report = restore_json(&mut sanitized, &mapping);

        assert_eq!(restore_report.restored_values, 6);
        assert_eq!(sanitized, original);
    }

    #[test]
    fn reuses_existing_mapping_tokens() {
        let mut first = json!({
            "items": [{ "name": "One", "login": { "password": "shared" } }]
        });
        let (mapping, _) = sanitize_json(&mut first, MappingFile::default());
        let first_token = first["items"][0]["login"]["password"].clone();

        let mut second = json!({
            "items": [{ "name": "Two", "notes": "shared" }]
        });
        let (mapping, report) = sanitize_json(&mut second, mapping);

        assert_eq!(report.total_mappings, 1);
        assert_eq!(second["items"][0]["notes"], first_token);
        assert_eq!(mapping.entries.len(), 1);
    }
}
