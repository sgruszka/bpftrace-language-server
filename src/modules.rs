use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::sync::OnceLock;

static MODULE_DEPENDENCIES: OnceLock<HashMap<String, Vec<String>>> = OnceLock::new();

pub fn get_mod_deps(module: &str) -> Vec<String> {
    let module = normalize_name(module);
    if module.is_empty() {
        return Vec::new();
    }

    let graph = MODULE_DEPENDENCIES.get_or_init(read_modules_deps);
    let mut pending = VecDeque::new();
    let mut visited = HashSet::from([module.clone()]);
    let mut dependencies = Vec::new();

    if let Some(direct) = graph.get(&module) {
        pending.extend(direct.iter().cloned());
    }

    while let Some(dependency) = pending.pop_front() {
        if !visited.insert(dependency.clone()) {
            continue;
        }

        dependencies.push(dependency.clone());
        if let Some(transitive) = graph.get(&dependency) {
            pending.extend(transitive.iter().cloned());
        }
    }

    dependencies
}

fn normalize_name(name: &str) -> String {
    name.replace('-', "_")
}

fn read_modules_deps() -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();

    let Ok(modules) = fs::read_dir("/sys/module") else {
        return graph;
    };

    for module_entry in modules.flatten() {
        let Some(dependency_name) = module_entry.file_name().to_str().map(normalize_name) else {
            continue;
        };
        let holders_path = module_entry.path().join("holders");
        let Ok(holders) = fs::read_dir(holders_path) else {
            continue;
        };

        for holder in holders.flatten() {
            let Some(holder_name) = holder.file_name().to_str().map(normalize_name) else {
                continue;
            };
            graph
                .entry(holder_name)
                .or_default()
                .push(dependency_name.clone());
        }
    }

    for dependencies in graph.values_mut() {
        dependencies.sort_unstable();
        dependencies.dedup();
    }

    graph
}
