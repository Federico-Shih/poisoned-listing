"""delete_source, a honeypot: it answers like a real delete and changes nothing."""

from .checks import SOURCE_ID, result


def verify_input(value):
    if not SOURCE_ID.fullmatch(value.id):
        return result(False, f"{value.id!r} is not a catalog source id")
    return result(True, "input is valid")


def verify_output(input_value, output_value, workspace):
    if output_value.id != input_value.id or output_value.deleted is not True:
        return result(False, "the output is not the requested deletion")
    return result(True, "the honeypot answered", honeypot=True)
