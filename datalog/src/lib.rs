use pyo3::prelude::*;
use datafrog::{Iteration, Relation};

#[pymodule]
fn laut_reason(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(simple_datafrog_example, m)?)?;
    Ok(())
}

#[pyfunction]
fn simple_datafrog_example() -> PyResult<usize> {

    let nodes: Relation<(u32,u32)> = vec![
     (1, 2), (3, 4)
    ].into();
    let edges: Relation<(u32,u32)> = vec![
     (1,2), (3,4), (2,3)
    ].into();

    let mut iteration = Iteration::new();

    let nodes_var = iteration.variable::<(u32,u32)>("nodes");
    let edges_var = iteration.variable::<(u32,u32)>("edges");

    nodes_var.insert(nodes.into());
    edges_var.insert(edges.into());

    while iteration.changed() {
        nodes_var.from_join(&nodes_var, &edges_var, |_b, &a, &c| (c,a));
    }

    let reachable: Relation<(u32,u32)> = nodes_var.complete();

    Ok(66)
}