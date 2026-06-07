//! Tree construction: walk the derivation graph and build
//! [`UnresolvedDerivation`] nodes, memoizing by drv_path.

use std::collections::BTreeMap;
use std::sync::Arc;

use lautr_core::store_path;

use crate::backend::Backend;
use crate::drv_json::{self, DrvJson};
use crate::types::{UnresolvedDerivation, UnresolvedOutput, UnresolvedReferencedInputs};

use super::{Error, Orchestrator};

impl<B: Backend> Orchestrator<B> {
    pub(super) fn build_unresolved(
        &mut self,
        drv_path: &str,
    ) -> Result<Arc<UnresolvedDerivation>, Error> {
        if let Some(existing) = self.tree_memo.get(drv_path) {
            return Ok(existing.clone());
        }

        let drv = self
            .derivations
            .get(drv_path)
            .ok_or_else(|| Error::DerivationNotFound(drv_path.to_owned()))?
            .clone();
        let (is_fixed_output, is_content_addressed) = drv_json::classify(&drv.outputs);

        let outputs = build_outputs(drv_path, &drv, is_content_addressed)?;
        let fod_out_path = if is_fixed_output {
            Some(
                drv.outputs
                    .get("out")
                    .and_then(|o| o.path.clone())
                    .ok_or_else(|| Error::FodMissingOut {
                        drv_path: drv_path.to_owned(),
                    })?,
            )
        } else {
            None
        };

        let inputs = if is_fixed_output {
            Vec::new()
        } else if is_content_addressed || self.allow_ia {
            let mut acc = Vec::with_capacity(drv.input_drvs.len());
            for (input_drv_path, input_ref) in &drv.input_drvs {
                let child = self.build_unresolved(input_drv_path)?;
                let mut referenced: BTreeMap<String, UnresolvedOutput> = BTreeMap::new();
                for output_name in &input_ref.outputs {
                    let output = child.outputs.get(output_name).ok_or_else(|| {
                        Error::UnknownReferencedOutput {
                            drv_path: input_drv_path.clone(),
                            output_name: output_name.clone(),
                        }
                    })?;
                    referenced.insert(output_name.clone(), output.clone());
                }
                acc.push(UnresolvedReferencedInputs {
                    derivation: child,
                    inputs: referenced,
                });
            }
            acc
        } else {
            return Err(Error::InputAddressedNotAllowed);
        };

        let unresolved = Arc::new(UnresolvedDerivation {
            drv_path: drv_path.to_owned(),
            name: drv.name.clone(),
            input_hash: store_path::extract_store_hash(drv_path)?,
            outputs,
            inputs,
            is_fixed_output,
            is_content_addressed,
            fod_out_path,
        });
        self.tree_memo
            .insert(drv_path.to_owned(), unresolved.clone());
        Ok(unresolved)
    }
}

/// Build the unresolved-output map for a derivation. Mirrors
/// `get_all_outputs_of_drv` in the Python.
fn build_outputs(
    drv_path: &str,
    drv: &DrvJson,
    is_content_addressed: bool,
) -> Result<BTreeMap<String, UnresolvedOutput>, Error> {
    let mut out = BTreeMap::new();
    for (output_name, output_ref) in &drv.outputs {
        let (input_hash, unresolved_path) = if is_content_addressed {
            (None, format!("{}${}", drv_path, output_name))
        } else {
            let path = output_ref.path.clone().ok_or_else(|| {
                Error::UnknownReferencedOutput {
                    drv_path: drv_path.to_owned(),
                    output_name: output_name.clone(),
                }
            })?;
            let hash = store_path::extract_store_hash(&path)?;
            (Some(hash), path)
        };
        out.insert(
            output_name.clone(),
            UnresolvedOutput {
                output_name: output_name.clone(),
                drv_path: drv_path.to_owned(),
                input_hash,
                unresolved_path,
            },
        );
    }
    Ok(out)
}
