use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub include_review_groups: bool,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            include_review_groups: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MergeAnalysis {
    pub summary: AnalysisSummary,
    pub high_confidence_merge_candidates: Vec<MergeCandidate>,
    pub same_account_site_different_passwords: Vec<PasswordConflict>,
    pub review_groups: Vec<ReviewGroup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    pub total_items: usize,
    pub login_items: usize,
    pub login_items_with_username_password: usize,
    pub duplicate_credential_groups: usize,
    pub duplicate_credential_items: usize,
    pub high_confidence_merge_groups: usize,
    pub high_confidence_merge_items: usize,
    pub password_conflict_groups: usize,
    pub review_groups: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MergeCandidate {
    pub id: String,
    pub account_hash: String,
    pub credential_hash: String,
    pub service: String,
    pub reason: String,
    pub items: Vec<ReportItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordConflict {
    pub id: String,
    pub account_hash: String,
    pub service: String,
    pub reason: String,
    pub password_variants: Vec<PasswordVariant>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordVariant {
    pub password_hash: String,
    pub items: Vec<ReportItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewGroup {
    pub id: String,
    pub account_hash: String,
    pub credential_hash: String,
    pub reason: String,
    pub service_summary: String,
    pub items: Vec<ReportItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportItem {
    pub item_index: usize,
    pub name: String,
    pub hosts: Vec<String>,
    pub uris: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MergeApplyOptions {
    pub manual_uri_groups: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct MergeApplyReport {
    pub merged_groups: usize,
    pub removed_items: usize,
    pub appended_login_uris: usize,
    pub appended_fields: usize,
    pub appended_password_history_entries: usize,
    pub appended_fido2_credentials: usize,
    pub appended_collection_ids: usize,
    pub preserved_scalar_values_as_fields: usize,
    pub manual_groups_matched: usize,
    pub manual_groups_unmatched: usize,
    pub skipped_conflict_groups: usize,
}

impl MergeApplyReport {
    fn absorb(&mut self, other: ItemMergeReport) {
        self.appended_login_uris += other.appended_login_uris;
        self.appended_fields += other.appended_fields;
        self.appended_password_history_entries += other.appended_password_history_entries;
        self.appended_fido2_credentials += other.appended_fido2_credentials;
        self.appended_collection_ids += other.appended_collection_ids;
        self.preserved_scalar_values_as_fields += other.preserved_scalar_values_as_fields;
    }
}

#[derive(Debug, Clone, Default)]
struct ItemMergeReport {
    appended_login_uris: usize,
    appended_fields: usize,
    appended_password_history_entries: usize,
    appended_fido2_credentials: usize,
    appended_collection_ids: usize,
    preserved_scalar_values_as_fields: usize,
}

#[derive(Debug, Clone)]
struct LoginRecord {
    item_index: usize,
    name: String,
    username_token: String,
    password_token: String,
    account_hash: String,
    credential_hash: String,
    password_hash: String,
    uris: Vec<String>,
    endpoints: Vec<Endpoint>,
    exact_keys: BTreeSet<String>,
    domain_keys: BTreeSet<String>,
    brand_keys: BTreeSet<String>,
    service_tokens: BTreeSet<String>,
    non_default_ports: BTreeSet<u16>,
    has_private_endpoint: bool,
    has_domain_endpoint: bool,
}

#[derive(Debug, Clone)]
struct Endpoint {
    host: String,
    kind: EndpointKind,
    registered_domain: Option<String>,
    brand_label: Option<String>,
    port: Option<u16>,
    is_private_address: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointKind {
    Domain,
    Address,
    AndroidPackage,
    Other,
}

#[derive(Debug)]
struct Component {
    indexes: Vec<usize>,
    reasons: BTreeSet<&'static str>,
}

pub fn analyze_merge_candidates(value: &Value, options: AnalyzeOptions) -> MergeAnalysis {
    let (total_items, login_items, records) = collect_login_records(value);

    let mut by_credential: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    let mut by_account: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for (record_index, record) in records.iter().enumerate() {
        by_credential
            .entry((record.username_token.clone(), record.password_token.clone()))
            .or_default()
            .push(record_index);
        by_account
            .entry(record.username_token.clone())
            .or_default()
            .push(record_index);
    }

    let duplicate_credential_groups = by_credential
        .values()
        .filter(|items| items.len() > 1)
        .count();
    let duplicate_credential_items = by_credential
        .values()
        .filter(|items| items.len() > 1)
        .map(Vec::len)
        .sum();

    let mut high_confidence_merge_candidates = Vec::new();
    let mut review_groups = Vec::new();

    for record_indexes in by_credential.values().filter(|items| items.len() > 1) {
        let components = related_components(record_indexes, &records);
        let mut high_confidence_item_count = 0;

        for component in components
            .iter()
            .filter(|component| component.indexes.len() > 1)
        {
            high_confidence_item_count += component.indexes.len();
            let group_records = component_records(component, &records);
            let first = group_records[0];

            high_confidence_merge_candidates.push(MergeCandidate {
                id: next_id("merge", high_confidence_merge_candidates.len() + 1),
                account_hash: first.account_hash.clone(),
                credential_hash: first.credential_hash.clone(),
                service: service_summary(&group_records),
                reason: summarize_reasons(&component.reasons),
                items: report_items(&group_records),
            });
        }

        if options.include_review_groups && high_confidence_item_count != record_indexes.len() {
            let group_records = record_indexes
                .iter()
                .map(|index| &records[*index])
                .collect::<Vec<_>>();
            let first = group_records[0];

            review_groups.push(ReviewGroup {
                id: next_id("review", review_groups.len() + 1),
                account_hash: first.account_hash.clone(),
                credential_hash: first.credential_hash.clone(),
                reason:
                    "same account/password appears in services that were not confidently related"
                        .to_owned(),
                service_summary: service_summary(&group_records),
                items: report_items(&group_records),
            });
        }
    }

    high_confidence_merge_candidates.sort_by(|left, right| {
        left.service
            .cmp(&right.service)
            .then_with(|| left.items[0].item_index.cmp(&right.items[0].item_index))
    });
    refresh_ids(
        "merge",
        high_confidence_merge_candidates
            .iter_mut()
            .map(|candidate| &mut candidate.id),
    );

    review_groups.sort_by(|left, right| {
        left.service_summary
            .cmp(&right.service_summary)
            .then_with(|| left.items[0].item_index.cmp(&right.items[0].item_index))
    });
    refresh_ids(
        "review",
        review_groups.iter_mut().map(|group| &mut group.id),
    );

    let mut same_account_site_different_passwords = password_conflicts(&by_account, &records);
    same_account_site_different_passwords.sort_by(|left, right| {
        left.service
            .cmp(&right.service)
            .then_with(|| left.account_hash.cmp(&right.account_hash))
    });
    refresh_ids(
        "conflict",
        same_account_site_different_passwords
            .iter_mut()
            .map(|conflict| &mut conflict.id),
    );

    let summary = AnalysisSummary {
        total_items,
        login_items,
        login_items_with_username_password: records.len(),
        duplicate_credential_groups,
        duplicate_credential_items,
        high_confidence_merge_groups: high_confidence_merge_candidates.len(),
        high_confidence_merge_items: high_confidence_merge_candidates
            .iter()
            .map(|candidate| candidate.items.len())
            .sum(),
        password_conflict_groups: same_account_site_different_passwords.len(),
        review_groups: review_groups.len(),
    };

    MergeAnalysis {
        summary,
        high_confidence_merge_candidates,
        same_account_site_different_passwords,
        review_groups,
    }
}

pub fn analysis_to_markdown(analysis: &MergeAnalysis) -> String {
    let mut output = String::new();
    output.push_str("# Bitwarden merge analysis report\n\n");
    output.push_str("This report is generated from a sanitized Bitwarden JSON export. ");
    output.push_str("Credential identifiers are stable short hashes of sanitized tokens, not original secrets.\n\n");

    output.push_str("## Summary\n\n");
    output.push_str(&format!(
        "- Total items: {}\n",
        analysis.summary.total_items
    ));
    output.push_str(&format!(
        "- Login items: {}\n",
        analysis.summary.login_items
    ));
    output.push_str(&format!(
        "- Login items with username and password: {}\n",
        analysis.summary.login_items_with_username_password
    ));
    output.push_str(&format!(
        "- Reused credential groups: {} groups, {} items\n",
        analysis.summary.duplicate_credential_groups, analysis.summary.duplicate_credential_items
    ));
    output.push_str(&format!(
        "- High-confidence merge candidates: {} groups, {} items\n",
        analysis.summary.high_confidence_merge_groups, analysis.summary.high_confidence_merge_items
    ));
    output.push_str(&format!(
        "- Same account/site with different passwords: {} groups\n",
        analysis.summary.password_conflict_groups
    ));
    output.push_str(&format!(
        "- Review-only reused credential groups: {}\n\n",
        analysis.summary.review_groups
    ));

    output.push_str("## High-confidence merge candidates\n\n");
    if analysis.high_confidence_merge_candidates.is_empty() {
        output.push_str("No high-confidence merge candidates found.\n\n");
    } else {
        for candidate in &analysis.high_confidence_merge_candidates {
            output.push_str(&format!(
                "### {}: {}\n\n",
                candidate.id,
                escape_markdown(&candidate.service)
            ));
            output.push_str(&format!(
                "- account_hash: `{}`\n- credential_hash: `{}`\n- reason: {}\n\n",
                candidate.account_hash,
                candidate.credential_hash,
                escape_markdown(&candidate.reason)
            ));
            write_items_table(&mut output, &candidate.items, None);
        }
    }

    output.push_str("## Same account/site with different passwords\n\n");
    if analysis.same_account_site_different_passwords.is_empty() {
        output.push_str("No same-account same-site password conflicts found.\n\n");
    } else {
        for conflict in &analysis.same_account_site_different_passwords {
            output.push_str(&format!(
                "### {}: {}\n\n",
                conflict.id,
                escape_markdown(&conflict.service)
            ));
            output.push_str(&format!(
                "- account_hash: `{}`\n- reason: {}\n\n",
                conflict.account_hash,
                escape_markdown(&conflict.reason)
            ));

            for variant in &conflict.password_variants {
                output.push_str(&format!("Password hash `{}`:\n\n", variant.password_hash));
                write_items_table(&mut output, &variant.items, None);
            }
        }
    }

    output.push_str("## Review-only reused credential groups\n\n");
    output.push_str("These groups reuse the same account/password, but the related services were ambiguous or mixed with unrelated services. They are not merge recommendations.\n\n");
    if analysis.review_groups.is_empty() {
        output.push_str("No review-only groups found.\n");
    } else {
        for group in &analysis.review_groups {
            output.push_str(&format!(
                "### {}: {}\n\n",
                group.id,
                escape_markdown(&group.service_summary)
            ));
            output.push_str(&format!(
                "- account_hash: `{}`\n- credential_hash: `{}`\n- reason: {}\n\n",
                group.account_hash,
                group.credential_hash,
                escape_markdown(&group.reason)
            ));
            write_items_table(&mut output, &group.items, None);
        }
    }

    output
}

pub fn apply_recommended_merges(value: &mut Value, options: MergeApplyOptions) -> MergeApplyReport {
    let analysis = analyze_merge_candidates(
        value,
        AnalyzeOptions {
            include_review_groups: false,
        },
    );
    let (_, _, records) = collect_login_records(value);
    let item_count = value
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();

    let mut report = MergeApplyReport {
        merged_groups: 0,
        removed_items: 0,
        appended_login_uris: 0,
        appended_fields: 0,
        appended_password_history_entries: 0,
        appended_fido2_credentials: 0,
        appended_collection_ids: 0,
        preserved_scalar_values_as_fields: 0,
        manual_groups_matched: 0,
        manual_groups_unmatched: 0,
        skipped_conflict_groups: 0,
    };

    if item_count == 0 {
        return report;
    }

    let mut union_find = UnionFind::new(item_count);
    let credential_by_item = records
        .iter()
        .map(|record| {
            (
                record.item_index,
                (
                    record.username_token.clone(),
                    record.password_token.clone(),
                    record.account_hash.clone(),
                    record.credential_hash.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for candidate in &analysis.high_confidence_merge_candidates {
        union_all(
            &mut union_find,
            candidate.items.iter().map(|item| item.item_index),
        );
    }

    for manual_group in &options.manual_uri_groups {
        let requested_uris = manual_group.iter().collect::<BTreeSet<_>>();
        let mut by_credential: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();

        for record in &records {
            if record.uris.iter().any(|uri| requested_uris.contains(uri)) {
                by_credential
                    .entry((&record.username_token, &record.password_token))
                    .or_default()
                    .push(record.item_index);
            }
        }

        let mut matched = false;
        for indexes in by_credential.values().filter(|indexes| indexes.len() > 1) {
            union_all(&mut union_find, indexes.iter().copied());
            matched = true;
        }

        if matched {
            report.manual_groups_matched += 1;
        } else {
            report.manual_groups_unmatched += 1;
        }
    }

    let mut merge_groups = union_find.groups();
    merge_groups.retain(|group| group.len() > 1);
    merge_groups.sort_by_key(|group| group.iter().copied().min().unwrap_or_default());

    let Some(items) = value.get_mut("items").and_then(Value::as_array_mut) else {
        return report;
    };

    let mut remove_indexes = BTreeSet::new();

    for mut group in merge_groups {
        group.sort_unstable();

        let Some(first_credential) = credential_by_item.get(&group[0]) else {
            continue;
        };

        if group
            .iter()
            .any(|index| credential_by_item.get(index) != Some(first_credential))
        {
            report.skipped_conflict_groups += 1;
            continue;
        }

        let primary_index = group[0];
        for source_index in group.iter().copied().skip(1) {
            let Some(source) = items.get(source_index).cloned() else {
                continue;
            };
            if let Some(target) = items.get_mut(primary_index) {
                report.absorb(merge_item(target, &source, source_index));
                remove_indexes.insert(source_index);
            }
        }

        report.merged_groups += 1;
    }

    for index in remove_indexes.iter().rev() {
        items.remove(*index);
    }
    report.removed_items = remove_indexes.len();

    report
}

fn collect_login_records(value: &Value) -> (usize, usize, Vec<LoginRecord>) {
    let Some(items) = value.get("items").and_then(Value::as_array) else {
        return (0, 0, Vec::new());
    };

    let mut records = Vec::new();
    let mut login_items = 0;

    for (item_index, item) in items.iter().enumerate() {
        if item.get("type").and_then(Value::as_i64) != Some(1) {
            continue;
        }

        login_items += 1;

        let Some(login) = item.get("login").and_then(Value::as_object) else {
            continue;
        };
        let Some(username_token) = login.get("username").and_then(Value::as_str) else {
            continue;
        };
        let Some(password_token) = login.get("password").and_then(Value::as_str) else {
            continue;
        };

        if username_token.is_empty() || password_token.is_empty() {
            continue;
        }

        let name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let uris = login
            .get("uris")
            .and_then(Value::as_array)
            .map(|uris| {
                uris.iter()
                    .filter_map(|uri| uri.get("uri").and_then(Value::as_str))
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let endpoints = uris
            .iter()
            .filter_map(|uri| parse_endpoint(uri))
            .collect::<Vec<_>>();

        let mut record = LoginRecord {
            item_index,
            name,
            username_token: username_token.to_owned(),
            password_token: password_token.to_owned(),
            account_hash: short_hash(&[username_token]),
            credential_hash: short_hash(&[username_token, password_token]),
            password_hash: short_hash(&[password_token]),
            uris,
            endpoints,
            exact_keys: BTreeSet::new(),
            domain_keys: BTreeSet::new(),
            brand_keys: BTreeSet::new(),
            service_tokens: BTreeSet::new(),
            non_default_ports: BTreeSet::new(),
            has_private_endpoint: false,
            has_domain_endpoint: false,
        };
        enrich_record(&mut record);
        records.push(record);
    }

    (items.len(), login_items, records)
}

fn merge_item(target: &mut Value, source: &Value, source_index: usize) -> ItemMergeReport {
    let mut report = ItemMergeReport::default();
    let Some(target_object) = target.as_object_mut() else {
        return report;
    };
    let Some(source_object) = source.as_object() else {
        return report;
    };

    if let Some(source_login) = source_object.get("login").and_then(Value::as_object) {
        if !target_object.contains_key("login") {
            target_object.insert("login".to_owned(), Value::Object(Map::new()));
        }

        let displaced_values = target_object
            .get_mut("login")
            .and_then(Value::as_object_mut)
            .map(|target_login| merge_login(target_login, source_login, source_index, &mut report))
            .unwrap_or_default();

        for (name, value) in displaced_values {
            add_preserved_scalar_field(target_object, name, &value, &mut report);
        }
    }

    append_object_array(
        target_object,
        source_object,
        "fields",
        &mut report.appended_fields,
    );
    append_object_array(
        target_object,
        source_object,
        "passwordHistory",
        &mut report.appended_password_history_entries,
    );
    append_object_array(
        target_object,
        source_object,
        "collectionIds",
        &mut report.appended_collection_ids,
    );
    merge_favorite(target_object, source_object);

    if let Some(source_notes) = source_object.get("notes") {
        match merge_value_field(target_object, "notes", source_notes) {
            MergeValueOutcome::Inserted | MergeValueOutcome::Unchanged => {}
            MergeValueOutcome::Displaced(value) => add_preserved_scalar_field(
                target_object,
                format!("merged item #{source_index} notes"),
                &value,
                &mut report,
            ),
        }
    }

    for (key, source_value) in source_object {
        if is_top_level_merge_key(key) || is_item_metadata_key(key) {
            continue;
        }

        match merge_value_field(target_object, key, source_value) {
            MergeValueOutcome::Inserted | MergeValueOutcome::Unchanged => {}
            MergeValueOutcome::Displaced(value) => add_preserved_scalar_field(
                target_object,
                format!("merged item #{source_index} {key}"),
                &value,
                &mut report,
            ),
        }
    }

    report
}

fn merge_login(
    target_login: &mut Map<String, Value>,
    source_login: &Map<String, Value>,
    source_index: usize,
    report: &mut ItemMergeReport,
) -> Vec<(String, Value)> {
    append_object_array(
        target_login,
        source_login,
        "uris",
        &mut report.appended_login_uris,
    );
    append_object_array(
        target_login,
        source_login,
        "fido2Credentials",
        &mut report.appended_fido2_credentials,
    );

    let mut displaced_values = Vec::new();
    for (key, source_value) in source_login {
        if matches!(key.as_str(), "uris" | "fido2Credentials") {
            continue;
        }

        match merge_value_field(target_login, key, source_value) {
            MergeValueOutcome::Inserted | MergeValueOutcome::Unchanged => {}
            MergeValueOutcome::Displaced(value) => {
                displaced_values.push((format!("merged item #{source_index} login.{key}"), value))
            }
        }
    }

    displaced_values
}

#[derive(Debug)]
enum MergeValueOutcome {
    Inserted,
    Unchanged,
    Displaced(Value),
}

fn merge_value_field(
    target_object: &mut Map<String, Value>,
    key: &str,
    source_value: &Value,
) -> MergeValueOutcome {
    match target_object.get(key) {
        None => {
            target_object.insert(key.to_owned(), source_value.clone());
            MergeValueOutcome::Inserted
        }
        Some(target_value) if target_value == source_value || is_empty_value(source_value) => {
            MergeValueOutcome::Unchanged
        }
        Some(target_value) if is_empty_value(target_value) => {
            target_object.insert(key.to_owned(), source_value.clone());
            MergeValueOutcome::Inserted
        }
        Some(_) => MergeValueOutcome::Displaced(source_value.clone()),
    }
}

fn append_object_array(
    target_object: &mut Map<String, Value>,
    source_object: &Map<String, Value>,
    key: &str,
    appended_count: &mut usize,
) {
    let Some(source_array) = source_object.get(key).and_then(Value::as_array) else {
        return;
    };

    if source_array.is_empty() {
        return;
    }

    if !target_object.contains_key(key) {
        target_object.insert(key.to_owned(), Value::Array(Vec::new()));
    }

    let Some(target_array) = target_object.get_mut(key).and_then(Value::as_array_mut) else {
        return;
    };

    for source_value in source_array {
        if !target_array
            .iter()
            .any(|target_value| target_value == source_value)
        {
            target_array.push(source_value.clone());
            *appended_count += 1;
        }
    }
}

fn merge_favorite(target_object: &mut Map<String, Value>, source_object: &Map<String, Value>) {
    if source_object.get("favorite").and_then(Value::as_bool) == Some(true) {
        target_object.insert("favorite".to_owned(), Value::Bool(true));
    }
}

fn add_preserved_scalar_field(
    target_object: &mut Map<String, Value>,
    name: String,
    value: &Value,
    report: &mut ItemMergeReport,
) {
    if is_empty_value(value) {
        return;
    }

    let field_value = value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string());
    let mut field = Map::new();
    field.insert("name".to_owned(), Value::String(name));
    field.insert("value".to_owned(), Value::String(field_value));
    field.insert("type".to_owned(), Value::Number(0.into()));

    let field_value = Value::Object(field);

    if !target_object.contains_key("fields") {
        target_object.insert("fields".to_owned(), Value::Array(Vec::new()));
    }

    let Some(fields) = target_object
        .get_mut("fields")
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    if !fields.iter().any(|existing| existing == &field_value) {
        fields.push(field_value);
        report.appended_fields += 1;
        report.preserved_scalar_values_as_fields += 1;
    }
}

fn is_empty_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(values) => values.is_empty(),
        Value::Object(values) => values.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

fn is_top_level_merge_key(key: &str) -> bool {
    matches!(
        key,
        "login" | "fields" | "passwordHistory" | "collectionIds" | "notes" | "favorite"
    )
}

fn is_item_metadata_key(key: &str) -> bool {
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
            | "name"
    )
}

#[derive(Debug)]
struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
        }
    }

    fn union(&mut self, left: usize, right: usize) {
        let left_root = self.find(left);
        let right_root = self.find(right);

        if left_root != right_root {
            self.parent[right_root] = left_root;
        }
    }

    fn find(&mut self, index: usize) -> usize {
        if self.parent[index] != index {
            self.parent[index] = self.find(self.parent[index]);
        }

        self.parent[index]
    }

    fn groups(&mut self) -> Vec<Vec<usize>> {
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();

        for index in 0..self.parent.len() {
            let root = self.find(index);
            groups.entry(root).or_default().push(index);
        }

        groups.into_values().collect()
    }
}

fn union_all(indexes: &mut UnionFind, mut values: impl Iterator<Item = usize>) {
    let Some(first) = values.next() else {
        return;
    };

    for value in values {
        indexes.union(first, value);
    }
}

fn enrich_record(record: &mut LoginRecord) {
    record.service_tokens.extend(tokenize(&record.name));

    for endpoint in &record.endpoints {
        match endpoint.kind {
            EndpointKind::AndroidPackage => {
                record
                    .exact_keys
                    .insert(format!("package:{}", endpoint.host));
            }
            EndpointKind::Address => {
                let key = endpoint
                    .port
                    .map(|port| format!("address:{}:{port}", endpoint.host))
                    .unwrap_or_else(|| format!("address:{}", endpoint.host));
                record.exact_keys.insert(key);
            }
            EndpointKind::Domain | EndpointKind::Other => {
                record.exact_keys.insert(format!("host:{}", endpoint.host));
            }
        }

        if let Some(domain) = &endpoint.registered_domain {
            record.domain_keys.insert(format!("domain:{domain}"));
            record.has_domain_endpoint = true;
            record.service_tokens.extend(tokenize(domain));
        }

        if let Some(brand_label) = &endpoint.brand_label {
            record.brand_keys.insert(format!("brand:{brand_label}"));
            record.service_tokens.insert(brand_label.clone());
        }

        if let Some(port) = endpoint.port.filter(|port| !is_default_port(*port)) {
            record.non_default_ports.insert(port);
        }

        record.has_private_endpoint |= endpoint.is_private_address;
        record.service_tokens.extend(tokenize(&endpoint.host));
    }
}

fn related_components(record_indexes: &[usize], records: &[LoginRecord]) -> Vec<Component> {
    let mut parent = (0..record_indexes.len()).collect::<Vec<_>>();
    let mut reasons = vec![BTreeSet::new(); record_indexes.len()];

    for left_pos in 0..record_indexes.len() {
        for right_pos in (left_pos + 1)..record_indexes.len() {
            let left = &records[record_indexes[left_pos]];
            let right = &records[record_indexes[right_pos]];

            if let Some(reason) = relation_reason(left, right) {
                union(left_pos, right_pos, &mut parent);
                reasons[left_pos].insert(reason);
                reasons[right_pos].insert(reason);
            }
        }
    }

    let mut grouped: BTreeMap<usize, Component> = BTreeMap::new();
    for pos in 0..record_indexes.len() {
        let root = find(pos, &mut parent);
        let component = grouped.entry(root).or_insert_with(|| Component {
            indexes: Vec::new(),
            reasons: BTreeSet::new(),
        });
        component.indexes.push(record_indexes[pos]);
        component.reasons.extend(reasons[pos].iter().copied());
    }

    grouped.into_values().collect()
}

fn relation_reason(left: &LoginRecord, right: &LoginRecord) -> Option<&'static str> {
    if intersects(&left.exact_keys, &right.exact_keys) {
        return Some("same normalized host or app package");
    }

    if intersects(&left.domain_keys, &right.domain_keys) {
        return Some("same registered domain");
    }

    if intersects(&left.brand_keys, &right.brand_keys) {
        return Some("same organization label across domains/packages");
    }

    if self_host_bridge(left, right) {
        return Some("matching self-host service evidence");
    }

    None
}

fn self_host_bridge(left: &LoginRecord, right: &LoginRecord) -> bool {
    let private_to_domain = (left.has_private_endpoint && right.has_domain_endpoint)
        || (right.has_private_endpoint && left.has_domain_endpoint);

    if !private_to_domain {
        return false;
    }

    if left
        .service_tokens
        .intersection(&right.service_tokens)
        .any(|token| token.len() >= 3)
    {
        return true;
    }

    intersects(&left.non_default_ports, &right.non_default_ports)
        && normalized_non_url_name(&left.name) == normalized_non_url_name(&right.name)
        && !normalized_non_url_name(&left.name).is_empty()
}

fn password_conflicts(
    by_account: &BTreeMap<String, Vec<usize>>,
    records: &[LoginRecord],
) -> Vec<PasswordConflict> {
    let mut conflicts = Vec::new();

    for record_indexes in by_account.values().filter(|items| items.len() > 1) {
        let components = related_components(record_indexes, records);

        for component in components
            .iter()
            .filter(|component| component.indexes.len() > 1)
        {
            let mut by_password: BTreeMap<&str, Vec<&LoginRecord>> = BTreeMap::new();

            for index in &component.indexes {
                let record = &records[*index];
                by_password
                    .entry(record.password_token.as_str())
                    .or_default()
                    .push(record);
            }

            if by_password.len() <= 1 {
                continue;
            }

            let group_records = component_records(component, records);
            let first = group_records[0];
            let password_variants = by_password
                .into_values()
                .map(|variant_records| PasswordVariant {
                    password_hash: variant_records[0].password_hash.clone(),
                    items: report_items(&variant_records),
                })
                .collect();

            conflicts.push(PasswordConflict {
                id: next_id("conflict", conflicts.len() + 1),
                account_hash: first.account_hash.clone(),
                service: service_summary(&group_records),
                reason: summarize_reasons(&component.reasons),
                password_variants,
            });
        }
    }

    conflicts
}

fn component_records<'a>(
    component: &Component,
    records: &'a [LoginRecord],
) -> Vec<&'a LoginRecord> {
    let mut group_records = component
        .indexes
        .iter()
        .map(|index| &records[*index])
        .collect::<Vec<_>>();
    group_records.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.item_index.cmp(&right.item_index))
    });
    group_records
}

fn report_items(records: &[&LoginRecord]) -> Vec<ReportItem> {
    let mut items = records
        .iter()
        .map(|record| {
            let hosts = record
                .endpoints
                .iter()
                .map(|endpoint| endpoint.host.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            ReportItem {
                item_index: record.item_index,
                name: record.name.clone(),
                hosts,
                uris: record.uris.clone(),
            }
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.item_index.cmp(&right.item_index))
    });
    items
}

fn service_summary(records: &[&LoginRecord]) -> String {
    let mut domains = BTreeSet::new();
    let mut brands = BTreeSet::new();
    let mut hosts = BTreeSet::new();

    for record in records {
        for endpoint in &record.endpoints {
            if let Some(domain) = &endpoint.registered_domain {
                domains.insert(domain.clone());
            }
            if let Some(brand) = &endpoint.brand_label {
                brands.insert(brand.clone());
            }
            hosts.insert(endpoint.host.clone());
        }
    }

    if domains.len() == 1 {
        return domains.into_iter().next().unwrap();
    }

    if domains.len() > 1 {
        return join_limited(domains.into_iter().collect(), 5);
    }

    if brands.len() == 1 {
        return brands.into_iter().next().unwrap();
    }

    if !hosts.is_empty() {
        return join_limited(hosts.into_iter().collect(), 5);
    }

    let names = records
        .iter()
        .map(|record| record.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    join_limited(names, 5)
}

fn summarize_reasons(reasons: &BTreeSet<&'static str>) -> String {
    if reasons.is_empty() {
        return "same account/password with related login endpoints".to_owned();
    }

    reasons.iter().copied().collect::<Vec<_>>().join("; ")
}

fn parse_endpoint(uri: &str) -> Option<Endpoint> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (scheme, authority) = split_scheme_authority(trimmed);
    let mut kind = match scheme {
        Some(scheme) if scheme.eq_ignore_ascii_case("android") => EndpointKind::AndroidPackage,
        Some(scheme) if scheme.eq_ignore_ascii_case("androidapp") => EndpointKind::AndroidPackage,
        _ => EndpointKind::Other,
    };

    let authority = authority?;
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = split_host_port(authority);
    let host = normalize_host(host)?;

    let mut domain = None;
    let mut brand_label = None;
    let mut is_private_address = false;

    if kind == EndpointKind::AndroidPackage {
        brand_label = package_brand_label(&host);
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        kind = EndpointKind::Address;
        is_private_address = is_private_ip(ip);
    } else if host.contains('.') {
        kind = EndpointKind::Domain;
        domain = registered_domain(&host);
        brand_label = domain
            .as_deref()
            .and_then(registered_domain_label)
            .filter(|label| !is_generic_label(label))
            .map(str::to_owned);
    }

    Some(Endpoint {
        host,
        kind,
        registered_domain: domain,
        brand_label,
        port,
        is_private_address,
    })
}

fn split_scheme_authority(uri: &str) -> (Option<&str>, Option<&str>) {
    if let Some((scheme, rest)) = uri.split_once("://") {
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .filter(|authority| !authority.is_empty());
        return (Some(scheme), authority);
    }

    let authority = uri
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty());
    (None, authority)
}

fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok());
        return (host, port);
    }

    let colon_count = authority.matches(':').count();
    if colon_count == 1
        && let Some((host, port)) = authority.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host, Some(port));
    }

    (authority, None)
}

fn normalize_host(host: &str) -> Option<String> {
    let normalized = host
        .trim()
        .trim_matches('.')
        .trim_matches('/')
        .to_ascii_lowercase();

    if normalized.is_empty() {
        None
    } else {
        Some(
            normalized
                .strip_prefix("www.")
                .unwrap_or(&normalized)
                .to_owned(),
        )
    }
}

fn registered_domain(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }

    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return None;
    }

    if labels.len() >= 3 {
        let suffix = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
        if is_multi_label_suffix(&suffix) {
            return Some(labels[labels.len() - 3..].join("."));
        }
    }

    Some(labels[labels.len() - 2..].join("."))
}

fn registered_domain_label(domain: &str) -> Option<&str> {
    domain.split('.').next()
}

fn is_multi_label_suffix(suffix: &str) -> bool {
    matches!(
        suffix,
        "ac.cn"
            | "co.jp"
            | "co.uk"
            | "com.au"
            | "com.cn"
            | "com.hk"
            | "edu.cn"
            | "edu.hk"
            | "gov.cn"
            | "ne.jp"
            | "net.au"
            | "net.cn"
            | "or.jp"
            | "org.cn"
            | "org.uk"
    )
}

fn package_brand_label(package: &str) -> Option<String> {
    package
        .split('.')
        .find(|label| !is_generic_label(label) && label.len() >= 3)
        .map(ToOwned::to_owned)
}

fn is_generic_label(label: &str) -> bool {
    matches!(
        label,
        "account"
            | "accounts"
            | "android"
            | "app"
            | "auth"
            | "blog"
            | "cloud"
            | "cn"
            | "co"
            | "com"
            | "dev"
            | "edu"
            | "gov"
            | "id"
            | "io"
            | "jp"
            | "login"
            | "mail"
            | "net"
            | "org"
            | "sso"
            | "uk"
            | "web"
            | "www"
    )
}

fn tokenize(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|token| token.len() >= 3)
        .filter(|token| !token.chars().all(|character| character.is_ascii_digit()))
        .filter(|token| !is_generic_label(token))
        .collect()
}

fn normalized_non_url_name(name: &str) -> String {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.contains("://") || normalized.parse::<IpAddr>().is_ok() {
        return String::new();
    }

    tokenize(&normalized)
        .into_iter()
        .collect::<Vec<_>>()
        .join("-")
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback() || (first & 0xfe00) == 0xfc00
        }
    }
}

fn is_default_port(port: u16) -> bool {
    matches!(port, 80 | 443)
}

fn intersects<T: Ord>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> bool {
    left.iter().any(|item| right.contains(item))
}

fn union(left: usize, right: usize, parent: &mut [usize]) {
    let left_root = find(left, parent);
    let right_root = find(right, parent);
    if left_root != right_root {
        parent[right_root] = left_root;
    }
}

fn find(index: usize, parent: &mut [usize]) -> usize {
    if parent[index] != index {
        parent[index] = find(parent[index], parent);
    }
    parent[index]
}

fn short_hash(parts: &[&str]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;

    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    format!("{hash:016x}")[..12].to_owned()
}

fn next_id(prefix: &str, index: usize) -> String {
    format!("{prefix}-{index:03}")
}

fn refresh_ids<'a>(prefix: &str, ids: impl Iterator<Item = &'a mut String>) {
    for (index, id) in ids.enumerate() {
        *id = next_id(prefix, index + 1);
    }
}

fn join_limited(values: Vec<String>, limit: usize) -> String {
    if values.is_empty() {
        return "(no host)".to_owned();
    }

    let extra = values.len().saturating_sub(limit);
    let mut shown = values
        .into_iter()
        .take(limit)
        .collect::<Vec<_>>()
        .join(", ");
    if extra > 0 {
        shown.push_str(&format!(", +{extra} more"));
    }
    shown
}

fn write_items_table(output: &mut String, items: &[ReportItem], password_hash: Option<&str>) {
    if password_hash.is_some() {
        output.push_str("| Item # | Password | Name | Hosts/packages | URIs |\n");
        output.push_str("| ---: | --- | --- | --- | --- |\n");
    } else {
        output.push_str("| Item # | Name | Hosts/packages | URIs |\n");
        output.push_str("| ---: | --- | --- | --- |\n");
    }

    for item in items {
        let hosts = if item.hosts.is_empty() {
            String::new()
        } else {
            item.hosts.join("<br>")
        };
        let uris = if item.uris.is_empty() {
            String::new()
        } else {
            item.uris.join("<br>")
        };

        if let Some(password_hash) = password_hash {
            output.push_str(&format!(
                "| {} | `{}` | {} | {} | {} |\n",
                item.item_index,
                password_hash,
                escape_markdown_table(&item.name),
                escape_markdown_table(&hosts),
                escape_markdown_table(&uris)
            ));
        } else {
            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                item.item_index,
                escape_markdown_table(&item.name),
                escape_markdown_table(&hosts),
                escape_markdown_table(&uris)
            ));
        }
    }

    output.push('\n');
}

fn escape_markdown(text: &str) -> String {
    text.replace('|', "\\|")
}

fn escape_markdown_table(text: &str) -> String {
    escape_markdown(text).replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reports_exact_host_merge_candidate() {
        let value = json!({
            "items": [
                login_item("A", "https://example.com", "u1", "p1"),
                login_item("B", "http://www.example.com/login", "u1", "p1")
            ]
        });

        let analysis = analyze_merge_candidates(&value, AnalyzeOptions::default());

        assert_eq!(analysis.high_confidence_merge_candidates.len(), 1);
        assert_eq!(analysis.high_confidence_merge_candidates[0].items.len(), 2);
        assert!(analysis.review_groups.is_empty());
    }

    #[test]
    fn relates_same_brand_across_domains_and_android_package() {
        let value = json!({
            "items": [
                login_item("Apple", "https://apple.com", "u1", "p1"),
                login_item("Apple ID", "https://appleid.apple.com", "u1", "p1"),
                login_item("Apple CN", "https://apple.com.cn", "u1", "p1"),
                login_item("App", "android://fingerprint@com.apple.android", "u1", "p1")
            ]
        });

        let analysis = analyze_merge_candidates(&value, AnalyzeOptions::default());

        assert_eq!(analysis.high_confidence_merge_candidates.len(), 1);
        assert_eq!(analysis.high_confidence_merge_candidates[0].items.len(), 4);
    }

    #[test]
    fn keeps_unrelated_same_credentials_in_review() {
        let value = json!({
            "items": [
                login_item("A", "https://example.com", "u1", "p1"),
                login_item("B", "https://unrelated.test", "u1", "p1")
            ]
        });

        let analysis = analyze_merge_candidates(&value, AnalyzeOptions::default());

        assert!(analysis.high_confidence_merge_candidates.is_empty());
        assert_eq!(analysis.review_groups.len(), 1);
    }

    #[test]
    fn reports_same_account_site_different_passwords() {
        let value = json!({
            "items": [
                login_item("A", "https://account.example.com", "u1", "p1"),
                login_item("B", "https://example.com", "u1", "p2")
            ]
        });

        let analysis = analyze_merge_candidates(&value, AnalyzeOptions::default());

        assert_eq!(analysis.same_account_site_different_passwords.len(), 1);
        assert_eq!(
            analysis.same_account_site_different_passwords[0]
                .password_variants
                .len(),
            2
        );
    }

    #[test]
    fn relates_self_hosted_private_and_public_when_service_tokens_match() {
        let value = json!({
            "items": [
                login_item("Immich", "https://immich.example.net", "u1", "p1"),
                login_item("Immich", "http://100.104.90.58:2283", "u1", "p1")
            ]
        });

        let analysis = analyze_merge_candidates(&value, AnalyzeOptions::default());

        assert_eq!(analysis.high_confidence_merge_candidates.len(), 1);
    }

    #[test]
    fn does_not_merge_same_ip_with_different_ports_without_service_evidence() {
        let value = json!({
            "items": [
                login_item("One", "http://100.104.90.58:2283", "u1", "p1"),
                login_item("Two", "http://100.104.90.58:3010", "u1", "p1")
            ]
        });

        let analysis = analyze_merge_candidates(&value, AnalyzeOptions::default());

        assert!(analysis.high_confidence_merge_candidates.is_empty());
        assert_eq!(analysis.review_groups.len(), 1);
    }

    #[test]
    fn applies_recommended_merge_preserving_item_and_field_order() {
        let mut value = json!({
            "items": [
                login_item("Example", "https://example.com", "u1", "p1"),
                login_item("Other", "https://other.example.com", "u1", "p1"),
                login_item("Keep", "https://keep.example", "u2", "p2")
            ]
        });

        let report = apply_recommended_merges(&mut value, MergeApplyOptions::default());
        let items = value["items"].as_array().unwrap();
        let first_item_keys = items[0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(report.merged_groups, 1);
        assert_eq!(report.removed_items, 1);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["name"], "Example");
        assert_eq!(items[1]["name"], "Keep");
        assert_eq!(first_item_keys, vec!["type", "name", "login"]);
        assert_eq!(
            items[0]["login"]["uris"],
            json!([
                { "uri": "https://example.com" },
                { "uri": "https://other.example.com" }
            ])
        );
    }

    #[test]
    fn applies_manual_uri_group_when_credentials_match() {
        let mut value = json!({
            "items": [
                login_item("Lan", "http://192.168.31.87:5000/", "u1", "p1"),
                login_item("Tailnet", "http://100.104.90.58:5000/", "u1", "p1")
            ]
        });

        let report = apply_recommended_merges(
            &mut value,
            MergeApplyOptions {
                manual_uri_groups: vec![vec![
                    "http://192.168.31.87:5000/".to_owned(),
                    "http://100.104.90.58:5000/".to_owned(),
                ]],
            },
        );

        assert_eq!(report.manual_groups_matched, 1);
        assert_eq!(report.merged_groups, 1);
        assert_eq!(value["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn skips_manual_uri_group_when_passwords_differ() {
        let mut value = json!({
            "items": [
                login_item("Lan", "http://192.168.31.87:5000/", "u1", "p1"),
                login_item("Tailnet", "http://100.104.90.58:5000/", "u1", "p2")
            ]
        });

        let report = apply_recommended_merges(
            &mut value,
            MergeApplyOptions {
                manual_uri_groups: vec![vec![
                    "http://192.168.31.87:5000/".to_owned(),
                    "http://100.104.90.58:5000/".to_owned(),
                ]],
            },
        );

        assert_eq!(report.manual_groups_unmatched, 1);
        assert_eq!(report.merged_groups, 0);
        assert_eq!(value["items"].as_array().unwrap().len(), 2);
    }

    fn login_item(name: &str, uri: &str, username: &str, password: &str) -> Value {
        json!({
            "type": 1,
            "name": name,
            "login": {
                "username": username,
                "password": password,
                "uris": [{ "uri": uri }]
            }
        })
    }
}
