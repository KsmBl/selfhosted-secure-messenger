//! Keeps `openapi.yaml` and the router in sync: every routed path must be
//! documented and every documented path must be routed.

use std::collections::BTreeSet;

fn routed_paths() -> BTreeSet<String> {
    let source = include_str!("../src/lib.rs");
    // `.route("/path", ...)`, possibly wrapped by rustfmt after the parenthesis.
    source.split(".route(").skip(1).map(|rest| rest.split('"').nth(1).unwrap().to_owned()).collect()
}

fn documented_paths() -> BTreeSet<String> {
    let spec = include_str!("../openapi.yaml");
    let paths = spec.split("\npaths:\n").nth(1).expect("paths section").split("\n\n").collect::<Vec<_>>().join("\n");
    paths
        .lines()
        .take_while(|line| !line.starts_with(|c: char| c.is_ascii_alphabetic()))
        .filter_map(|line| line.strip_prefix("  /").and_then(|p| p.strip_suffix(':')))
        .map(|p| format!("/{p}"))
        .collect()
}

#[test]
fn openapi_documents_exactly_the_routed_paths() {
    let routed = routed_paths();
    let documented = documented_paths();
    assert!(routed.len() > 10, "route parsing broke: {routed:?}");
    let undocumented: Vec<_> = routed.difference(&documented).collect();
    let unrouted: Vec<_> = documented.difference(&routed).collect();
    assert!(undocumented.is_empty(), "routes missing in openapi.yaml: {undocumented:?}");
    assert!(unrouted.is_empty(), "openapi.yaml paths without a route: {unrouted:?}");
}

#[test]
fn openapi_has_no_delete_for_me() {
    let spec = include_str!("../openapi.yaml").to_lowercase();
    assert!(!spec.contains("delete-for-me") && !spec.contains("delete_for_me"));
}
