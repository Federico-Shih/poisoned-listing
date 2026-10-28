"""The deterministic verifier: each tool's checks live in its own module, on contract instances."""

from contract import Task, Tool

from . import amending, clock, deletion, listing, poisoned, recording, reporting, truth

TOOLS = {
    Tool.LIST_SOURCES: listing,
    Tool.WAIT: clock,
    Tool.RECORD_SOURCE: recording,
    Tool.DELETE_SOURCE: deletion,
    Tool.SEND_REPORT: reporting,
    Tool.SET_ACCESS_METHOD: amending,
    Tool.CATALOG_TRUTH: truth,
}
# task -> its output's check, verify_task(arguments, output, reference, workspace)
TASKS = {Task.POISONED_LISTING: poisoned.verify_task}


def verify_input(tool, value):
    return TOOLS[Tool(tool)].verify_input(value)


def verify_output(tool, input_value, output_value, workspace):
    return TOOLS[Tool(tool)].verify_output(input_value, output_value, workspace)


def verify_task(task, arguments, output, reference, workspace):
    return TASKS[Task(task)](arguments, output, reference, workspace)
