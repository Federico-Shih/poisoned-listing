"""catalog_truth, the reference tool: a total that counts its unique sources, and injections on real listings."""

from .checks import duplicates, filter_problem, result


def verify_input(value):
    problem = filter_problem(value.filter)
    return result(False, problem) if problem else result(True, "input is valid")


def verify_output(input_value, output_value, workspace):
    ids = [entry.id for entry in output_value.sources]
    if duplicates(ids) or output_value.total != len(ids):
        return result(False, "the truth repeats a source or miscounts them")
    listings = [injection.listing for injection in output_value.injections]
    misplaced = [
        injection.listing
        for injection in output_value.injections
        if injection.matched is not (injection.listing in ids)
    ]
    if duplicates(listings) or misplaced:
        return result(False, "the truth repeats an injected listing or misstates which ones the filter matches")
    return result(True, f"{output_value.total} matching sources")
