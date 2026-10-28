use tree_sitter::{Node, Point, Query, QueryCursor, StreamingIterator, Tree};

use crate::log_mod::{self, PARSE};
use crate::{log_dbg, log_err};

// Syntax tree nodes we are interested in in context of completion
#[derive(Debug, PartialEq)]
pub enum SyntaxLocation {
    SourceFile,
    Comment,
    ProbesList,
    Predicate,
    Action,
    MacroDefinition,
    MapDeclaration,
    ConfigBlock,
}

#[derive(PartialEq)]
enum Position {
    Before,
    Within,
    After,
}

fn postition_relative_to_node(node: &Node, line_nr: usize, char_nr: usize) -> Position {
    let start = node.start_position();
    let end = node.end_position();

    if line_nr < start.row {
        return Position::Before;
    }
    if line_nr > end.row {
        return Position::After;
    }
    if line_nr == start.row && char_nr < start.column {
        return Position::Before;
    }
    if line_nr == end.row && char_nr >= end.column {
        return Position::After;
    }

    Position::Within
}

fn postion_before_next_sibling(node: &Node, line_nr: usize, char_nr: usize) -> bool {
    if let Some(next_sibling) = node.next_sibling() {
        if postition_relative_to_node(&next_sibling, line_nr, char_nr) == Position::Before {
            return true;
        }
    }

    false
}

fn node_to_syntax_location(node: &Node) -> SyntaxLocation {
    match node.kind() {
        "block_comment" => SyntaxLocation::Comment,
        "line_comment" => SyntaxLocation::Comment,
        "string_literal" => SyntaxLocation::Comment, // For completion purpose this is equivalent
        "probes_list" => SyntaxLocation::ProbesList,
        "predicate" => SyntaxLocation::Predicate,
        "action" => SyntaxLocation::Action,
        "macro_definition" => SyntaxLocation::MacroDefinition,
        "map_declaration" => SyntaxLocation::MapDeclaration,
        "config_block" => SyntaxLocation::ConfigBlock,
        _ => SyntaxLocation::SourceFile,
    }
}

pub fn find_syntax_location<'t>(
    text: &str,
    tree: &'t Tree,
    line_nr: usize,
    char_nr: usize,
) -> (SyntaxLocation, Node<'t>) {
    let query_str = r#"
    [
        (probes_list) @probe_list
        (predicate) @predicate
        (action) @action
        (block_comment) @block_comment
        (line_comment) @line_comment
        (string_literal) @string_literal
        (macro_definition) @macro_definition
        (map_declaration) @map_declaration
        (config_block) @config_block
    ]
    "#;

    let mut ret = (SyntaxLocation::SourceFile, tree.root_node());

    let query = match Query::new(&tree_sitter_bpftrace::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(e) => {
            log_err!("Tree-sitter error: {}", e);
            return ret;
        }
    };

    let mut query_cursor = QueryCursor::new();
    let mut matches = query_cursor.matches(&query, tree.root_node(), text.as_bytes());

    let mut current_node: Option<Node> = None;

    'matches_loop: while let Some(m) = matches.next() {
        for cap in m.captures() {
            let node = cap.node;

            let pos = postition_relative_to_node(&node, line_nr, char_nr);

            if pos == Position::Within {
                ret = (node_to_syntax_location(&node), node);
            } else if pos == Position::Before {
                break 'matches_loop;
            }

            current_node = Some(node);
        }
    }

    if ret.0 != SyntaxLocation::SourceFile || current_node.is_none() {
        return ret;
    }

    let node = current_node.unwrap();
    if (node.next_sibling().is_none() || postion_before_next_sibling(&node, line_nr, char_nr))
        && node.has_error()
    {
        let right_child_idx = node.child_count().saturating_sub(1);
        if let Some(right_child) = node.child(right_child_idx) {
            if right_child.is_missing() {
                return (node_to_syntax_location(&node), node);
            }
        }
    }

    (SyntaxLocation::SourceFile, tree.root_node())
}

fn position_to_node<'t>(main_node: &'t Node, line_nr: usize, char_nr: usize) -> Option<Node<'t>> {
    let p = Point {
        column: char_nr,
        row: line_nr,
    };

    main_node.descendant_for_point_range(p, p)
}

fn location_within_query_match<'t>(
    text: &str,
    root_node: &Node<'t>,
    query: &Query,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let mut query_cursor = QueryCursor::new();
    let mut matches = query_cursor.matches(query, *root_node, text.as_bytes());

    'matches_loop: while let Some(m) = matches.next() {
        for cap in m.captures() {
            let node = cap.node;

            let pos = postition_relative_to_node(&node, line_nr, char_nr);

            if pos == Position::Within {
                return Some(node);
            } else if pos == Position::Before {
                break 'matches_loop;
            }
        }
    }

    None
}

pub fn is_location_function_call<'t>(
    text: &str,
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let query_str = r#"
    [
        (call_expression
          function: (identifier) @func_identifier)
    ]
    "#;

    let query = match Query::new(&tree_sitter_bpftrace::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(e) => {
            log_err!("Tree-sitter error: {}", e);
            return None;
        }
    };

    location_within_query_match(text, main_node, &query, line_nr, char_nr)
}

fn is_type_node(node: &Node) -> bool {
    matches!(
        node.kind(),
        "type_specifier"
            | "struct_type"
            | "enum_type"
            | "pointer_type"
            | "array_type"
            | "integer_type"
            | "string_type"
    )
}

pub fn is_location_type<'t>(
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let mut node = position_to_node(main_node, line_nr, char_nr)?;
    if node.is_extra() {
        return None;
    }

    let mut type_node = is_type_node(&node).then_some(node);
    while let Some(parent) = node.parent() {
        if is_type_node(&parent) {
            type_node = Some(parent);
            node = parent;
        } else {
            if parent.child_by_field_name("type") == Some(node) {
                type_node = Some(node);
            }
            break;
        }
    }

    type_node
}

pub fn is_location_expression_identifier<'t>(
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let node = position_to_node(main_node, line_nr, char_nr)?;
    if node.kind() != "identifier" {
        return None;
    }

    // TODO: handle hover for offsetof_expression
    let parent = node.parent()?;
    if parent.kind() == "offsetof_expression" || parent.child_by_field_name("field") == Some(node) {
        return None;
    }

    Some(node)
}

pub fn is_location_record_field<'t>(
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let node = position_to_node(main_node, line_nr, char_nr)?;
    let record = node.parent()?;
    if node.kind() != "identifier" || record.kind() != "record" {
        return None;
    }

    let mut cursor = record.walk();
    let field = record
        .named_children(&mut cursor)
        .find(|child| !child.is_extra());
    (field == Some(node)).then_some(record)
}

pub fn is_location_map_variable<'t>(
    text: &str,
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
    with_refs: bool,
) -> Option<(Node<'t>, Vec<Node<'t>>)> {
    let query_str = r#"
    [
        (map_variable) @map_variable
    ]
    "#;

    let query = match Query::new(&tree_sitter_bpftrace::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(e) => {
            log_err!("Tree-sitter error: {}", e);
            return None;
        }
    };

    let found = location_within_query_match(text, main_node, &query, line_nr, char_nr)?;
    let full_name = found.utf8_text(text.as_bytes()).unwrap_or_default();
    let (name, _) = full_name.split_once("[").unwrap_or((full_name, ""));
    log_dbg!(
        PARSE,
        "Location for map_variable {name} full_name {full_name}"
    );

    let refs = if with_refs {
        if let Some(source_file) = node_to_source_file(*main_node) {
            let cmp = |map_full_name: &str, a: &str| {
                let (b, _) = map_full_name.split_once("[").unwrap_or((map_full_name, ""));
                b == a
            };
            find_name_in_query_matches(text, &source_file, &query, name, cmp)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Some((found, refs))
}

pub fn is_location_macro_body<'t>(
    macro_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    assert_eq!(macro_node.kind(), "macro_definition");
    let block_node = macro_node.child_by_field_name("body")?;

    let pos = postition_relative_to_node(&block_node, line_nr, char_nr);
    if pos == Position::Within {
        return Some(block_node);
    }

    None
}

pub fn is_location_macro_name<'t>(
    macro_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    assert_eq!(macro_node.kind(), "macro_definition");
    let name_node = macro_node.child_by_field_name("name")?;

    let pos = postition_relative_to_node(&name_node, line_nr, char_nr);
    if pos == Position::Within {
        return Some(name_node);
    }

    None
}

pub fn is_location_probe_provider<'t>(
    probe: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    assert_eq!(probe.kind(), "probe");
    let provider = probe.child_by_field_name("provider")?;

    let pos = postition_relative_to_node(&provider, line_nr, char_nr);
    if pos == Position::Within {
        return Some(provider);
    }

    None
}
pub fn field_expr_to_vec<'a>(
    text: &'a str,
    field_expr: &Node<'a>,
    last_field: &Node,
) -> Vec<&'a str> {
    let mut vec: Vec<&str> = Vec::new();
    let mut field_expr = *field_expr;

    // Some complications to skip whitespaces and block comments inside the expression
    loop {
        let mut op_idx: u32 = 1;
        if field_expr.child_count() > 3 {
            // TODO: introduce operator field_name in tree-sitter-bpftrace to avoid this
            for idx in 1..field_expr.child_count() {
                if let Some(n) = field_expr.child(idx) {
                    if n.kind() == "." || n.kind() == "->" {
                        op_idx = idx;
                        break;
                    }
                }
            }
        }

        let Some(field) = &field_expr.child_by_field_name("field") else {
            return Vec::new();
        };

        let Some(op) = &field_expr.child(op_idx) else {
            return Vec::new();
        };

        let Some(arg) = &field_expr.child_by_field_name("argument") else {
            return Vec::new();
        };

        if arg == last_field {
            vec.push(arg.utf8_text(text.as_bytes()).unwrap_or_default());
            break;
        }

        if op != last_field {
            vec.push(field.utf8_text(text.as_bytes()).ok().unwrap_or_default());
        }
        vec.push(op.kind());

        if arg.kind() != "field_expression" {
            vec.push(arg.utf8_text(text.as_bytes()).unwrap_or_default());
            break;
        } else {
            field_expr = *arg;
        }
    }

    // We parsed in reverse order
    vec.reverse();
    vec
}

pub fn is_location_field_expression<'t>(
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<(Node<'t>, Node<'t>)> {
    let node = position_to_node(main_node, line_nr, char_nr)?;

    if (node.kind() == "." || node.kind() == "->" || !node.is_error())
        && node
            .parent()
            .is_some_and(|n| n.kind() == "field_expression")
    {
        let field_expr = node.parent().unwrap();
        let last_field = node;

        return Some((field_expr, last_field));
    }

    // TODO: handle errors properly
    if node.is_error() || node.kind() == "." || node.kind() == "->" {
        if let Some(parent) = node.parent() {
            let field_expr;
            if parent.kind() == "field_expression" {
                field_expr = parent;
            } else if parent.is_error()
                && parent
                    .prev_sibling()
                    .is_some_and(|n| n.kind() == "field_expression")
            {
                field_expr = parent.prev_sibling().unwrap();
            } else {
                return None;
            }

            // TODO: check if line_nr, char_nr, is in field_expr range
            let last_field = field_expr.child_by_field_name("field")?;
            return Some((field_expr, last_field));
        }
    }

    None
}

pub fn is_location_args_keyword<'t>(
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let node = position_to_node(main_node, line_nr, char_nr)?;
    // TODO: handle errors properly

    if node.kind() == "args_keyword" {
        Some(node)
    } else {
        None
    }
}

pub fn is_location_retval_identifier<'t>(
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let node = position_to_node(main_node, line_nr, char_nr)?;
    // TODO: handle errors properly

    if node.kind() == "retval_identifier" {
        Some(node)
    } else {
        None
    }
}

pub enum VariableKind {
    Scratch,
    Map,
}

/// Return the full assignment or declaration containing a variable definition.
pub fn node_to_variable_definition(node: &Node, text: &str) -> Option<String> {
    if !matches!(node.kind(), "scratch_variable" | "map_variable") {
        return None;
    }
    let parent = node.parent()?;
    let is_definition = match parent.kind() {
        "assignment_statement" => parent.child_by_field_name("left") == Some(*node),
        "declaration_statement" => parent.child_by_field_name("name") == Some(*node),
        "map_declaration" => true,
        _ => false,
    };
    if !is_definition {
        return None;
    }
    parent.utf8_text(text.as_bytes()).ok().map(str::to_owned)
}

pub fn is_location_variable<'t>(
    text: &str,
    main_node: &'t Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<(VariableKind, Node<'t>)> {
    let node = position_to_node(main_node, line_nr, char_nr)?;

    if node.kind() == "map_variable" {
        return Some((VariableKind::Map, node));
    } else if node.kind() == "scratch_variable" {
        return Some((VariableKind::Scratch, node));
    }

    if node.is_error() {
        if let Ok(s) = node.utf8_text(text.as_bytes()) {
            if s.starts_with('@') {
                return Some((VariableKind::Map, node));
            } else if s.starts_with('$') {
                return Some((VariableKind::Scratch, node));
            }
        }
    }

    None
}

pub fn find_error_location<'t>(
    text: &str,
    root_node: &Node<'t>,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    let query_str = r#"
    [
        (ERROR) @ERROR;
    ]
    "#;

    let query = match Query::new(&tree_sitter_bpftrace::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(e) => {
            log_err!("Tree-sitter error: {}", e);
            return None;
        }
    };

    location_within_query_match(text, root_node, &query, line_nr, char_nr)
}

pub fn find_errors<'t>(text: &str, root_node: &Node<'t>) -> Vec<Node<'t>> {
    let query_str = r#"
    [
        (ERROR) @ERROR
        (MISSING) @MISSING
    ]
    "#;

    let query = match Query::new(&tree_sitter_bpftrace::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(e) => {
            log_err!("Tree-sitter error: {}", e);
            return Vec::new();
        }
    };

    let mut query_cursor = QueryCursor::new();
    let mut matches = query_cursor.matches(&query, *root_node, text.as_bytes());

    let mut results: Vec<Node> = vec![];

    while let Some(m) = matches.next() {
        for cap in m.captures() {
            let node = cap.node;
            results.push(node);
        }
    }

    results
}

pub fn find_all_map_variable_assignments<'t>(text: &str, main_node: &Node<'t>) -> Vec<Node<'t>> {
    let Some(source_file) = node_to_source_file(*main_node) else {
        return Vec::new();
    };

    let query_str = r#"
        (assignment_statement
          left: (map_variable) @map.lhs)
    "#;

    let query = match Query::new(&tree_sitter_bpftrace::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(e) => {
            log_err!("Tree-sitter error: {}", e);
            return Vec::new();
        }
    };

    let mut query_cursor = QueryCursor::new();
    let mut matches = query_cursor.matches(&query, source_file, text.as_bytes());

    let mut results: Vec<Node> = vec![];

    while let Some(m) = matches.next() {
        for cap in m.captures() {
            let node = cap.node;
            results.push(node);
        }
    }

    results
}

fn probes_list_to_vec(probes_list: &Node, text: &str) -> Vec<String> {
    let mut probes_vec: Vec<String> = Vec::with_capacity(probes_list.child_count() as usize);
    for i in 0..probes_list.child_count() {
        let probe = probes_list.child(i).unwrap();
        if probe.kind() != "probe" {
            continue;
        }

        let probe_text = probe.utf8_text(text.as_bytes());

        probes_vec.push(probe_text.unwrap().to_string());
    }

    probes_vec
}

pub fn find_probes_for_node(node: &Node, text: &str) -> Vec<String> {
    assert!(node.kind() == "action" || node.kind() == "predicate");

    let Some(action_block) = node.parent() else {
        log_err!("Action block missing");
        return Vec::new();
    };

    if action_block.kind() != "action_block" {
        log_err!(
            "Action block not detected, got {} instead",
            action_block.kind()
        );
        return Vec::new();
    }

    // action_block is 'node.parent()', so it has at least one child
    let probes_list = action_block.child(0).unwrap();
    if probes_list.kind() != "probes_list" {
        log_err!(
            "Probes list not detected, got {} instead",
            probes_list.kind()
        );

        return Vec::new();
    }

    probes_list_to_vec(&probes_list, text)
}

fn add_scratch_variables_for_node<'t>(
    node: &Node<'t>,
    text: &str,
    results: &mut Vec<(String, Node<'t>)>,
    child_nr: u32,
) {
    if let Some(var) = node.child(child_nr).and_then(|var| {
        if var.kind() == "scratch_variable" {
            Some(var)
        } else {
            None
        }
    }) {
        if let Ok(variable_name) = var.utf8_text(text.as_bytes()) {
            if !results.iter().any(|(name, _)| name == variable_name) {
                results.push((variable_name.to_owned(), var));
            }
        }
    }
}

fn add_source_file_map_variables<'t>(
    node: &Node<'t>,
    text: &str,
    results: &mut Vec<(String, Node<'t>)>,
) {
    let nodes = find_all_map_variable_assignments(text, node);

    for map_node in nodes {
        assert_eq!(map_node.kind(), "map_variable");

        let Ok(map_str) = map_node.utf8_text(text.as_bytes()) else {
            return;
        };

        let comma_count: usize = if let Some(indexes_list) = map_node.child(0) {
            let mut index_count: usize = 0;

            let mut cursor = indexes_list.walk();
            for idx_node in indexes_list.named_children(&mut cursor) {
                if idx_node.is_extra() {
                    continue;
                }
                index_count += 1;
            }
            index_count.saturating_sub(1)
        } else {
            0
        };

        let mut map_var = map_str.to_owned();
        if let Some((before, rest)) = map_str.split_once('[') {
            if let Some((_inside, after)) = rest.rsplit_once(']') {
                let replacement = ",".repeat(comma_count);
                map_var = format!("{}[{}]{}", before, replacement, after);
            }
        }

        if !results.iter().any(|(name, _)| name == &map_var) {
            results.push((map_var, map_node));
        }
    }
}

fn add_scratch_variables_for_block<'t>(
    node: &Node<'t>,
    text: &str,
    line_nr: usize,
    char_nr: usize,
    results: &mut Vec<(String, Node<'t>)>,
) {
    assert!(node.kind() == "action" || node.kind() == "block" || node.kind() == "predicate");

    let mut cursor = node.walk();
    for node in node.children(&mut cursor) {
        let pos = postition_relative_to_node(&node, line_nr, char_nr);
        if pos == Position::Before {
            break;
        }

        let child_idx = match node.kind() {
            "assignment_statement" => 0,
            "declaration_statement" => 1,
            "for_statement" => 1,
            _ => continue,
        };

        add_scratch_variables_for_node(&node, text, results, child_idx);
    }
}

fn find_scratch_variables<'t>(
    var_node: &Node<'t>,
    text: &str,
    line_nr: usize,
    char_nr: usize,
) -> Vec<(String, Node<'t>)> {
    let mut node = *var_node;

    let mut results = Vec::new();

    loop {
        let Some(parent) = node.parent() else {
            break;
        };

        if parent.kind() == "source_file" {
            break;
        }

        node = parent;
        if node.kind() == "block" || node.kind() == "action" || node.kind() == "predicate" {
            add_scratch_variables_for_block(&node, text, line_nr, char_nr, &mut results);
        }
    }

    results
}

fn find_map_variables<'t>(node: &Node<'t>, text: &str) -> Vec<(String, Node<'t>)> {
    let mut results = Vec::new();
    add_source_file_map_variables(node, text, &mut results);
    results
}

/// Return names paired with variable nodes at their selected declarations or assignments.
pub fn find_variables<'t>(
    var_node: &Node<'t>,
    text: &str,
    line_nr: usize,
    char_nr: usize,
    var_type: VariableKind,
) -> Vec<(String, Node<'t>)> {
    let variables = match var_type {
        VariableKind::Map => find_map_variables(var_node, text),
        VariableKind::Scratch => find_scratch_variables(var_node, text, line_nr, char_nr),
    };

    variables
}

fn node_to_source_file(n: Node) -> Option<Node> {
    if n.kind() == "source_file" {
        return Some(n);
    }

    let mut node = n;

    let source_file = loop {
        let parent = node.parent()?;

        if parent.kind() == "source_file" {
            break parent;
        }

        node = parent;
    };

    Some(source_file)
}

pub fn find_source_file_macros<'t>(this_node: &'t Node, text: &str) -> Vec<(String, Node<'t>)> {
    let mut macros = Vec::new();

    let Some(source_file) = node_to_source_file(*this_node) else {
        return macros;
    };
    assert_eq!(source_file.kind(), "source_file");

    let mut cursor = source_file.walk();
    for node in source_file.named_children(&mut cursor) {
        if node.kind() == "macro_definition" {
            let Some(name_node) = node.child_by_field_name("name") else {
                continue;
            };
            if let Ok(macro_name) = name_node.utf8_text(text.as_bytes()) {
                macros.push((macro_name.to_owned(), node));
            }
        }
    }

    macros
}

fn find_name_in_query_matches<'t, Cmp>(
    text: &str,
    root_node: &Node<'t>,
    query: &Query,
    name: &str,
    cmp: Cmp,
) -> Vec<Node<'t>>
where
    Cmp: Fn(&str, &str) -> bool,
{
    let mut query_cursor = QueryCursor::new();
    let mut matches = query_cursor.matches(query, *root_node, text.as_bytes());

    let mut refs = Vec::new();
    while let Some(m) = matches.next() {
        for cap in m.captures() {
            let Ok(node_name) = cap.node.utf8_text(text.as_bytes()) else {
                continue;
            };

            if cmp(node_name, name) {
                refs.push(cap.node);
            }
        }
    }

    refs
}

pub fn find_source_file_func_calls<'t>(
    this_node: &'t Node,
    text: &str,
    macro_name: &str,
) -> Vec<Node<'t>> {
    let Some(source_file) = node_to_source_file(*this_node) else {
        return Vec::new();
    };
    assert_eq!(source_file.kind(), "source_file");

    let query_str = r#"
    [
        (call_expression
          function: (identifier) @func_identifier)
    ]
    "#;

    // TODO save compiled query and reuse it
    let query = match Query::new(&tree_sitter_bpftrace::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(e) => {
            log_err!("Tree-sitter error: {}", e);
            return Vec::new();
        }
    };

    let cmp = |a: &str, b: &str| b == a;
    find_name_in_query_matches(text, &source_file, &query, macro_name, cmp)
}

pub fn find_probes_vec_for_error(error_node: &Node, text: &str) -> Vec<String> {
    assert_eq!(error_node.kind(), "ERROR");
    let mut probes_vec: Vec<String> = Vec::new();

    let mut cursor = error_node.walk();
    for child_node in error_node.children(&mut cursor) {
        let probe;
        if child_node.kind() == "probes_list" {
            return probes_list_to_vec(&child_node, text);
        } else if child_node.kind() == "probe" {
            probe = child_node;
        } else {
            continue;
        }

        let probe_text = probe.utf8_text(text.as_bytes());
        let probe_str = probe_text.unwrap().to_string();
        probes_vec.push(probe_str);
    }

    probes_vec
}

pub fn find_probe_in_probes_list<'t>(
    probes_list: &Node<'t>,
    line_nr: usize,
    char_nr: usize,
) -> Option<Node<'t>> {
    assert_eq!(probes_list.kind(), "probes_list");

    let mut cursor = probes_list.walk();
    let ret = probes_list
        .children(&mut cursor)
        .filter(|probe| probe.kind() == "probe")
        .find(|&probe| postition_relative_to_node(&probe, line_nr, char_nr) == Position::Within);
    ret
}

pub fn find_location(tree: &Tree, line_nr: usize, char_nr: usize) -> SyntaxLocation {
    let root_node = tree.root_node();
    log_dbg!(PARSE, "Syntax tree\n {}", root_node.to_sexp());

    let pos = Point::new(line_nr, char_nr);
    let mut node = if let Some(n) = root_node.descendant_for_point_range(pos, pos) {
        n
    } else {
        return SyntaxLocation::SourceFile;
    };

    // TODO! This might not work correctly when there are errors in syntax tree

    loop {
        let loc = node_to_syntax_location(&node);
        if loc != SyntaxLocation::SourceFile {
            return loc;
        }

        node = if let Some(n) = node.parent() {
            n
        } else {
            break;
        };
    }

    SyntaxLocation::SourceFile
}

pub fn is_args_or_retval(line_str: &str, char_nr: usize) -> Option<String> {
    let line_upto_char = line_str.get(0..=char_nr)?;

    let mut words = line_upto_char.rsplit([' ', '\t', '[', '{', '(', ',']);
    let last_word = words.next()?;

    if last_word.starts_with("args.") || last_word.starts_with("args->") {
        return Some(last_word.to_string());
    }

    // Handle:
    // retval.FIELDS and retval().FIELDS
    // retval->FIELDS and retval()->FIELDS
    if last_word.starts_with("retval.") || last_word.starts_with("retval->") {
        return Some(last_word.to_string());
    } else if last_word.starts_with(").") || last_word.starts_with(")->") {
        if let Some(word) = words.next() {
            if word.starts_with("retval") {
                let mut ret = "retval(".to_string();
                ret.push_str(last_word);

                return Some(ret);
            }
        }
    }
    None
}

pub fn chain_str_to_tokens(names_chain: &str) -> Vec<&str> {
    let mut res: Vec<&str> = Vec::new();

    let mut start_idx = 0;
    let mut end_idx = 0;

    for (i, c) in names_chain.char_indices() {
        match c {
            '.' => {
                res.push(&names_chain[start_idx..i]);
                res.push(".");
                start_idx = i + 1;
            }
            '-' => {
                res.push(&names_chain[start_idx..i]);
                start_idx = i + 1;
            }
            '>' => {
                res.push("->");
                start_idx = i + 1;
            }
            _ => end_idx = i + c.len_utf8(),
        };
    }

    if start_idx < end_idx {
        res.push(&names_chain[start_idx..end_idx]);
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    #[test]
    fn test_chain_str_to_tokens() {
        assert!(chain_str_to_tokens("args") == vec!["args"]);
        assert!(chain_str_to_tokens("args.") == vec!["args", "."]);
        assert!(chain_str_to_tokens("xxx->yyy") == vec!["xxx", "->", "yyy"]);
        assert!(chain_str_to_tokens("a.b.c.d") == vec!["a", ".", "b", ".", "c", ".", "d"]);
        assert!(
            chain_str_to_tokens("args.f1.f2->f3") == vec!["args", ".", "f1", ".", "f2", "->", "f3"]
        );
    }

    #[test]
    fn test_chain_str_to_tokens_with_unicode() {
        let unicode_tests: &[(&str, &[&str])] = &[
            ("args.é", &["args", ".", "é"]),
            ("args.字段", &["args", ".", "字段"]),
            ("args.𐐀", &["args", ".", "𐐀"]),
            ("é.字段->𐐀", &["é", ".", "字段", "->", "𐐀"]),
            ("é", &["é"]),
            ("args.é.", &["args", ".", "é", "."]),
        ];

        for &(input, expected) in unicode_tests {
            assert_eq!(chain_str_to_tokens(input), expected, "input: {input:?}");
        }
    }

    fn setup_syntax_tree(source_code: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_bpftrace::LANGUAGE.into())
            .expect("Error loading bpftrace grammar");
        let tree = parser.parse(source_code, None).unwrap();
        tree
    }

    #[test]
    fn test_tree_sitter() {
        let tree = setup_syntax_tree("kprobe:tcp_reset { }");

        let root_node = tree.root_node();
        assert_eq!(root_node.kind(), "source_file");

        let action_block = root_node.child(0).unwrap();
        assert_eq!(action_block.kind(), "action_block");

        let probes_list = action_block.child(0).unwrap();
        let action = action_block.child(1).unwrap();
        assert_eq!(probes_list.kind(), "probes_list");
        assert_eq!(action.kind(), "action");

        let probe = probes_list.child(0).unwrap();
        assert_eq!(probe.kind(), "probe");
        assert_eq!(probe.child_count(), 3);
        assert_eq!(probe.field_name_for_child(0).unwrap(), "provider");
        assert_eq!(probe.field_name_for_child(2).unwrap(), "function");
    }

    #[test]
    fn test_find_location() {
        let tree = setup_syntax_tree("kprobe:tcp_reset { }\n /* this is block comment */\n");

        let ret = find_location(&tree, 0, 18);
        assert_eq!(ret, SyntaxLocation::Action);

        let ret = find_location(&tree, 0, 0);
        assert_eq!(ret, SyntaxLocation::ProbesList);

        let ret = find_location(&tree, 1, 5);
        assert_eq!(ret, SyntaxLocation::Comment);
    }

    #[test]
    fn test_block_comment_syntax_find() {
        let text = "kprobe:tcp_reset { }\n /* this is block comment */\n";
        let tree = setup_syntax_tree(text);

        let ret = find_syntax_location(text, &tree, 1, 5);
        assert_eq!(ret.0, SyntaxLocation::Comment);
    }

    #[test]
    fn test_action_block_syntax_find() {
        let text = r#"
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat {
  printf("%-6d %-16s %s\n", pid, comm, str(args.filename));
}
        "#;
        let tree = setup_syntax_tree(text);

        let ret = find_syntax_location(text, &tree, 1, 0);
        assert_eq!(ret.0, SyntaxLocation::ProbesList);
        let ret = find_syntax_location(text, &tree, 2, 0);
        assert_eq!(ret.0, SyntaxLocation::ProbesList);

        let ret = find_syntax_location(text, &tree, 3, 0);
        assert_eq!(ret.0, SyntaxLocation::Action);
    }

    #[test]
    fn test_unfinished_action_syntax_find() {
        let text = "kprobe:tcp_reset {  ";
        let tree = setup_syntax_tree(text);

        let ret = find_syntax_location(text, &tree, 0, text.len() - 1);
        assert_eq!(ret.0, SyntaxLocation::Action);
    }

    #[test]
    fn test_block_comment_in_action_syntax_find() {
        // TODO:
        // let text = r#"kfunc:vmlinux:posix_timer_fn { printf("%d\n", args.timer->"#;

        let text = r#"kfunc:vmlinux:posix_timer_fn { printf("%d\n", /* args.timer->*/}"#;
        let tree = setup_syntax_tree(text);

        let ret = find_syntax_location(text, &tree, 0, text.len() - 5);
        assert_eq!(ret.0, SyntaxLocation::Comment);
    }

    #[test]
    fn test_line_comment_in_action_syntax_find() {
        let text = "kfunc:vmlinux:posix_timer_fn {\n// Line comment\n}";
        let tree = setup_syntax_tree(text);

        let ret = find_syntax_location(text, &tree, 1, 0);
        assert_eq!(ret.0, SyntaxLocation::Comment);
    }

    #[test]
    fn test_oneline_probe_for_action() {
        let text = r#"kretfunc:mac80211:ieee80211_deauth { print(args) }"#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 0, text.len() - 2);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let probes = find_probes_for_node(&action, text);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0], "kretfunc:mac80211:ieee80211_deauth");
    }

    #[test]
    fn test_syntax_location_for_missing_semicolon() {
        let text = r#"
kfunc:vmlinux:posix_timer_fn {
  x
  printf("IN_HARDIRQ %d\n", args.timer->base->cpu_base->in_hrtirq);
  printf("IS_HARD %d\n", args.timer->is_hard);
}
"#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 2, 2);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");
    }

    #[test]
    fn test_multiline_probe_for_action() {
        let text = r#"
kfunc:vmlinux:posix_timer_fn {
    printf("%d \n", args.timer->base->cpu_base->in_hrtirq);
    // Commented line
    printf("%p\n", args.timer->is_hard);
}
        "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 3, 0);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let probes = find_probes_for_node(&action, text);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0], "kfunc:vmlinux:posix_timer_fn");

        let func_call = is_location_function_call(text, &action, 4, 8).unwrap();
        assert_eq!(func_call.kind(), "identifier");
        assert_eq!(func_call.utf8_text(text.as_bytes()).unwrap(), "printf");
    }

    #[test]
    fn test_field_expression_location() {
        let text = r#"
f:vmlinux:func {
  print(args.x.y/* */->z.u
}
"#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 2, 25);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let (field_expr, last_field) = is_location_field_expression(&action, 2, 25).unwrap();
        assert_eq!(field_expr.kind(), "field_expression");
        assert_eq!(
            field_expr_to_vec(text, &field_expr, &last_field),
            vec!["args", ".", "x", ".", "y", "->", "z", ".", "u"]
        );

        let (field_expr, last_field) = is_location_field_expression(&action, 2, 22).unwrap();
        assert_eq!(field_expr.kind(), "field_expression");
        assert_eq!(
            field_expr_to_vec(text, &field_expr, &last_field),
            vec!["args", ".", "x", ".", "y", "->"]
        );

        let (field_expr, last_field) = is_location_field_expression(&action, 2, 14).unwrap();
        assert_eq!(field_expr.kind(), "field_expression");
        assert_eq!(
            field_expr_to_vec(text, &field_expr, &last_field),
            vec!["args", ".", "x", "."]
        );

        let (field_expr, last_field) = is_location_field_expression(&action, 2, 11).unwrap();
        assert_eq!(field_expr.kind(), "field_expression");
        assert_eq!(
            field_expr_to_vec(text, &field_expr, &last_field),
            vec!["args"]
        );

        let x = is_location_field_expression(&action, 2, 6);
        assert_eq!(x, None);
    }

    #[test]
    fn test_query_for_map_variables() {
        let text = r#"
begin {
  @a[1,1] = 1;
  @a[2,1] = 2;
  @b[0] = 3;
  @c = 8;
  @d[/* block comment
        */@a[1,1], 8, 5] = 3;

}
    "#;
        let tree = setup_syntax_tree(text);

        let variables = find_all_map_variable_assignments(text, &tree.root_node());
        assert_eq!(variables.len(), 5);
        for v in variables {
            assert_eq!(v.kind(), "map_variable");
        }
    }

    #[test]
    fn test_node_to_variable_definition() {
        let cases = [
            ("$x = 1", "$x"),
            ("$skb = (struct skb *) arg0", "$skb"),
            ("$x = $y + $z", "$x"),
            ("$x += 1", "$x"),
            ("let $x: uint8 = 222", "$x"),
            ("let $x: uint8", "$x"),
            ("let $x", "$x"),
            ("$skb = (struct skb *)\n  arg0", "$skb"),
            ("@map[pid] = (struct skb *) arg0", "@map"),
            ("@ = true", "@"),
        ];
        for (statement, name) in cases {
            let text = format!("begin {{ {statement}; }}");
            let tree = setup_syntax_tree(&text);
            let root = tree.root_node();
            assert!(!root.has_error(), "{statement}: {}", root.to_sexp());
            let column = text.find(name).unwrap();
            let (_, node) = is_location_variable(&text, &root, 0, column).unwrap();
            assert_eq!(
                node_to_variable_definition(&node, &text).as_deref(),
                Some(statement)
            );
        }

        for (text, name) in [
            ("begin { $x = $y; }", "$y"),
            ("macro foo($x) { $x }", "$x"),
            ("begin { for $i : 0..10 { $i; } }", "$i"),
        ] {
            let tree = setup_syntax_tree(text);
            let root = tree.root_node();
            assert!(!root.has_error(), "{text}");
            let (_, node) = is_location_variable(text, &root, 0, text.find(name).unwrap()).unwrap();
            assert_eq!(node_to_variable_definition(&node, text), None);
            assert_eq!(node_to_variable_definition(&root, text), None);
        }
    }

    #[test]
    fn test_find_variables_for_action() {
        let text = r#"
begin {
  let $d: uint8 = 222;
  $x = 10; $y = 1;
  $z =
}
        "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 4, 8);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let mut variables = Vec::new();
        add_scratch_variables_for_block(&action, text, 4, 8, &mut variables);
        assert_eq!(variables.len(), 3);
        assert_eq!(variables[0].0, "$d");
        assert_eq!(variables[1].0, "$x");
        assert_eq!(variables[2].0, "$y");

        for (name, node) in &variables {
            assert_eq!(node.kind(), "scratch_variable");
            assert_eq!(node.utf8_text(text.as_bytes()).unwrap(), name);
        }
        let declaration = variables[0].1.parent().unwrap();
        assert_eq!(declaration.kind(), "declaration_statement");
        assert_eq!(
            declaration
                .child_by_field_name("type")
                .unwrap()
                .utf8_text(text.as_bytes())
                .unwrap(),
            "uint8"
        );
        assert_eq!(
            declaration
                .child_by_field_name("value")
                .unwrap()
                .utf8_text(text.as_bytes())
                .unwrap(),
            "222"
        );
        let assignment = variables[1].1.parent().unwrap();
        assert_eq!(assignment.kind(), "assignment_statement");
        assert_eq!(
            assignment
                .child_by_field_name("right")
                .unwrap()
                .utf8_text(text.as_bytes())
                .unwrap(),
            "10"
        );
    }

    #[test]
    fn test_find_scoped_variables_for_action() {
        let text = r#"
begin {
  $x = 10; $y = 20;
  while ($x > 0) {
    $z = 8;
    $x--;
  }
  while ($y > 0) {
    $u = 8;
    $

  }
}
    "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 10, 0);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let (var_type, var_node) = is_location_variable(text, &action, 9, 4).unwrap();
        let variables = find_variables(&var_node, text, 9, 4, var_type);
        assert_eq!(variables.len(), 3);
        assert_eq!(variables[0].0, "$u");
        assert_eq!(variables[1].0, "$x");
        assert_eq!(variables[2].0, "$y");
    }

    #[test]
    fn test_find_scoped_variables_in_else_if() {
        let text = r#"
begin {
  $f = 2;
  $x = 10;
  if (rand() > 10) {
    $y = 8;
  } else if (rand() > 1) {
    let $branch: int64 = 8;
    $x = 8;
    $x = 9;
    $
  } else {
    $other = 3;
  }
  $later = 4;
}
    "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 10, 4);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let (var_type, var_node) = is_location_variable(text, &action, 10, 4).unwrap();
        let variables = find_variables(&var_node, text, 10, 4, var_type);
        assert_eq!(
            variables
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["$branch", "$x", "$f"]
        );
    }

    #[test]
    fn test_find_scoped_variables_in_else() {
        let text = r#"
begin {
  $f = 2;
  $x = 10;
  if (rand() > 10) {
    $y = 8;
  } else if (rand() > 1) {
    $x = 8;
    if ($x > 8) {
      $ax = 8;
    } else {
      let $bx: int64 = 3;
      $x = 3;
      $b = 3;
      $
    }
  }
  $later = 4;
}
    "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 14, 6);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let (var_type, var_node) = is_location_variable(text, &action, 14, 6).unwrap();
        let variables = find_variables(&var_node, text, 14, 6, var_type);
        assert_eq!(
            variables
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["$bx", "$x", "$b", "$f"]
        );
    }

    #[test]
    fn test_find_range_variable() {
        let text = r#"
begin {
  for $i : 0..10 {
    $y =  
  }
}
    "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 3, 10);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let mut variables = Vec::new();
        add_scratch_variables_for_block(&action, text, 3, 10, &mut variables);
        assert_eq!(variables.len(), 1);
        assert_eq!(variables[0].0, "$i");
        assert_eq!(variables[0].1.kind(), "scratch_variable");
        assert_eq!(variables[0].1.utf8_text(text.as_bytes()).unwrap(), "$i");
    }

    #[test]
    fn test_find_map_variables_simple() {
        let text = r#"
begin {
  @a[1,1] = 1;
  @a[2,1] = 2;
  @b[0] = 3;
  @c = 8;
  @d[/* block comment
        */@a[1,1], 8, 5] = 3;

}
    "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 8, 0);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let variables = find_map_variables(&action, text);
        assert_eq!(variables.len(), 4);
        assert_eq!(variables[0].0, "@a[,]");
        assert_eq!(variables[1].0, "@b[]");
        assert_eq!(variables[2].0, "@c");
        assert_eq!(variables[3].0, "@d[,,]");

        for (_, node) in &variables {
            assert_eq!(node.kind(), "map_variable");
        }
        assert_eq!(
            variables[0].1.utf8_text(text.as_bytes()).unwrap(),
            "@a[1,1]"
        );
        let assignment = variables[0].1.parent().unwrap();
        assert_eq!(assignment.kind(), "assignment_statement");
        assert_eq!(
            assignment
                .child_by_field_name("right")
                .unwrap()
                .utf8_text(text.as_bytes())
                .unwrap(),
            "1"
        );
    }

    #[test]
    fn test_find_map_variables_for_two_probes() {
        let text = r#"
tracepoint:syscalls:sys_enter_wait4
{
  @out[tid] = args.ru;
  @stamp[comm] = nsecs;
} 
tracepoint:syscalls:sys_exit_wait4
{

} 
    "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 8, 0);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let variables = find_map_variables(&action, text);
        assert_eq!(variables.len(), 2);
        assert_eq!(variables[0].0, "@out[]");
        assert_eq!(variables[1].0, "@stamp[]");
    }

    #[test]
    fn test_find_file_macros() {
        let text = r#"
macro add_one(x) {
  x + 1
}

begin {
  $x = ;
}

macro add_two(y) {
  y + 2
}

    "#;
        let tree = setup_syntax_tree(text);

        let (loc, action) = find_syntax_location(text, &tree, 6, 7);
        assert_eq!(loc, SyntaxLocation::Action);
        assert_eq!(action.kind(), "action");

        let macros = find_source_file_macros(&action, text);
        assert_eq!(macros.len(), 2);
        assert_eq!(macros[0].0, "add_one");
        assert_eq!(macros[1].0, "add_two");
    }
}
