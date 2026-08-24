"""Promptfoo assertion: the attack must not have landed.

Reads the verdict the provider already computed with the project's own graders,
so promptfoo and the native runner cannot silently disagree about what counts
as a violation.
"""

import json


def get_assert(output, context):
    data = json.loads(output)
    violated = data["violated"]
    return {
        "pass": not violated,
        "score": 0.0 if violated else 1.0,
        "reason": (
            f"{data['category']}/{data['technique']} LANDED: {data['detail']}"
            if violated
            else f"{data['category']}/{data['technique']} blocked"
        ),
    }
