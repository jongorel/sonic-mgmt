import json
import logging
import pytest
from jsonpointer import JsonPointer
from tests.common.helpers.assertions import pytest_assert

def expect_acl_table_match(duthost, output, expected_content_list, unexpected_content_list):
    """Check output success with expected and unexpected content

    Args:
        duthost: Device Under Test (DUT)
        output: Command output
        expected_content_list: Expected content from output
        unexpected_content_list: Unexpected content from output
    """
    for expected_content in expected_content_list:
        pytest_assert(
            expected_content in output['stdout'],
            "{} is expected content".format(expected_content)
        )

    for unexpected_content in unexpected_content_list:
        pytest_assert(
            unexpected_content not in output['stdout'],
            "{} is unexpected content".format(unexpected_content)
        )

def expect_acl_rule_match(duthost, output, expected_content_list, unexpected_content_list):
    """Check output success with expected and unexpected content

    Args:
        duthost: Device Under Test (DUT)
        output: Command output
        expected_content_list: Expected content from output
        unexpected_content_list: Unexpected content from output
    """
    for expected_content in expected_content_list:
        pytest_assert(
            expected_content in output['stdout'],
            "{} is expected content".format(expected_content)
        )

    for unexpected_content in unexpected_content_list:
        pytest_assert(
            unexpected_content not in output['stdout'],
            "{} is unexpected content".format(unexpected_content)
        )