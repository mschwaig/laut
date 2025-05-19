

from types import MappingProxyType
from laut.nix.types import (
    UnresolvedOutput,
    UnresolvedReferencedInputs,
)

def signature_to_string_map(signature):
    return dict(map(
        lambda key: (key, signature["out"]["nix"][key]["path"]),
        signature["out"]["nix"]
    ))

def signature_to_string_map_with_drv_path(signature, drv_path):
    """Convert signature outputs to a map with full derivation output names."""
    return dict(map(
        lambda key: (f"{drv_path}${key}", signature["out"]["nix"][key]["path"]),
        signature["out"]["nix"]
    ))

def inputs_to_string_list(inputs: set[UnresolvedReferencedInputs]) -> list[str]:
    result = []

    for referenced_inputs in inputs:
        for output_name, unresolved_output in referenced_inputs.inputs.items():
            formatted_string = f"{unresolved_output.drv_path}${output_name}"
            result.append(formatted_string)

    return result
def outputs_to_string_list(outputs: MappingProxyType[str, 'UnresolvedOutput']) -> list[str]:
    result = []

    for output_name, unresolved_output in outputs.items():
        formatted_string = f"{unresolved_output.drv_path}${output_name}"
        result.append(formatted_string)

    return result
