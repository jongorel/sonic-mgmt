import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

def expect_acl_table_match_multiple_bindings(duthost, table_name, expected_first_line_content, expected_bindings):
    """Check if acl table show as expected
    Acl table with multiple bindings will show as such

    Table_Name  Table_Type  Ethernet4   Table_Description   ingress
                            Ethernet8
                            Ethernet12
                            Ethernet16

    So we must have separate checks for first line and bindings
    """
    cmds = "show acl table {}".format(table_name)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # Ignore first two lines display. lines less than 3 means no output
    # Use empty list if no output
    lines = output['stdout'].splitlines()
    first_line = [] if len(lines) < 3 else lines[2].split()
    # Ignore the status column
    expected_len = len(expected_first_line_content)
    if len(first_line) >= expected_len:
        first_line = first_line[0:expected_len]

    pytest_assert(set(expected_first_line_content) == set(first_line), "ACL table definition doesn't match")
    bindings = [line.strip() for line in lines[3:]]
    #Second element of the first line is the first binding
    bindings.append(first_line[2])

    pytest_assert(set(bindings) == set(expected_bindings))

def expect_acl_rule_match(duthost, rulename, expected_content_list):
    """Check if acl rule shows as expected"""

    cmds = "show acl rule | grep {}".format(rulename)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    lines = output['stdout'].splitlines()
    actual_list = lines[0].split()

    # Ignore the status column
    expected_len = len(expected_content_list)
    if len(actual_list) >= expected_len:
        actual_list = actual_list[0:expected_len]

    pytest_assert(set(expected_content_list) == set(actual_list), "ACL rule does not match!")

def expect_acl_rule_removed(duthost, rulename):
    """Check if ACL rule has been successfully removed"""

    cmds = "show acl rule {}".format(rulename)
    output = duthost.shell(cmds)

    removed = len(output['stdout'].splitlines()) <= 2

    pytest_assert(removed, "'{}' showed a rule, this following rule should have been removed: {}".format(cmds, output['stdout']))
    
def dynamic_acl_create_table_type(duthost):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE_TYPE", 
            "value": { 
                "TEST_DYNAMICACL_TYPE" : { 
                "MATCHES": ["DST_IP","DST_IPV6","ETHER_TYPE","IN_PORTS"], 
                "ACTIONS": ["PACKET_ACTION","COUNTER"], 
                "BIND_POINTS": ["PORT"] 
                }                        
            }                                
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_table(duthost):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE/TEST_DYNAMIC_TABLE", 
            "value": { 
                "policy_desc": "TEST_DYNAMIC_TABLE", 
                "type": "TEST_DYNAMICACL_TYPE", 
                "stage": "INGRESS", 
                "ports": ["Ethernet4","Ethernet8","Ethernet12","Ethernet16","Ethernet20","Ethernet24","Ethernet28","Ethernet32","Ethernet36","Ethernet40","Ethernet44","Ethernet48","Ethernet52","Ethernet56","Ethernet60","Ethernet64","Ethernet68","Ethernet72","Ethernet76","Ethernet80","Ethernet84","Ethernet88","Ethernet92","Ethernet96"] 
            }                        
        }
    ]

    expected_bindings = ["Ethernet4","Ethernet8","Ethernet12","Ethernet16","Ethernet20","Ethernet24","Ethernet28","Ethernet32","Ethernet36","Ethernet40","Ethernet44","Ethernet48","Ethernet52","Ethernet56","Ethernet60","Ethernet64","Ethernet68","Ethernet72","Ethernet76","Ethernet80","Ethernet84","Ethernet88","Ethernet92","Ethernet96"] 
    expected_first_line = ["TEST_DYNAMIC_TABLE", "TEST_DYNAMICACL_TYPE", "Ethernet4", "TEST_DYNAMIC_TABLE", "ingress"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_table_match_multiple_bindings(duthost, "TEST_DYNAMIC_TABLE", expected_first_line, expected_bindings)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_duplicate_table(duthost):
    """Create a duplicate ACL table type that should fail"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE/TEST_DYNAMIC_TABLE", 
            "value": { 
                "policy_desc": "TEST_DYNAMIC_TABLE", 
                "type": "TEST_DYNAMICACL_TYPE", 
                "stage": "INGRESS", 
                "ports": ["Ethernet4","Ethernet8","Ethernet12","Ethernet16","Ethernet20","Ethernet24","Ethernet28","Ethernet32","Ethernet36","Ethernet40","Ethernet44","Ethernet48","Ethernet52","Ethernet56","Ethernet60","Ethernet64","Ethernet68","Ethernet72","Ethernet76","Ethernet80","Ethernet84","Ethernet88","Ethernet92","Ethernet96"] 
            }                        
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_forward_rules(duthost):
    """Create forward ACL rules"""

    json_patch = [ 
        { 
            "op": "add", 
            "path": "/ACL_RULE", 
            "value": { 
                "TEST_DYNAMIC_TABLE|RULE_1": {
                    "DST_IP": "10.10.10.1/32", 
                    "PRIORITY": "9999", 
                    "PACKET_ACTION": "FORWARD" 
                }, 
                "TEST_DYNAMIC_TABLE|RULE_2": {
                    "DST_IPV6": "fc02::1/128", 
                    "PRIORITY": "9998", 
                    "PACKET_ACTION": "FORWARD" 
                }
            }                                                                                                                               
        } 
    ] 

    expected_rule_1_content = ["TEST_DYNAMIC_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP:", "10.10.10.1/32"]
    expected_rule_2_content = ["TEST_DYNAMIC_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6:",  "fc02::1/128"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
        expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)
    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_create_drop_rule(duthost):
    """Create a drop rule"""

    json_patch = [
        { 
            "op": "add", 
            "path": "/ACL_RULE/TEST_DYNAMIC_TABLE|RULE_3", 
            "value": { 
                "PRIORITY": "9997", 
                "PACKET_ACTION": "DROP", 
                "IN_PORTS": "Ethernet4" 
            }                                                                                                                               
        } 
    ]

    expected_rule_content = ["TEST_DYNAMIC_TABLE", "RULE_3", "9997" , "DROP", "IN_PORTS:", "Ethernet4"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_drop_rule(duthost):
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_RULE/TEST_DYNAMIC_TABLE|RULE_3", 
            "value":{}                                                                                                                               
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_removed(duthost, "RULE_3")
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_replace_nonexistant_rule(duthost):
    json_patch = [ 
        { 
            "op": "replace", 
            "path": "/ACL_RULE/TEST_DYNAMIC_TABLE|RULE_10", 
            "value": { 
                "DST_IP": "10.10.10.2/32", 
                "PRIORITY": "9999", 
                "PACKET_ACTION": "FORWARD" 
            }                                                                                                                               
        }
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_replace_rules(duthost):
    json_patch = [ 
        { 
            "op": "replace", 
            "path": "/ACL_RULE/TEST_DYNAMIC_TABLE|RULE_1", 
            "value": { 
                "DST_IP": "10.10.10.2/32", 
                "PRIORITY": "9999", 
                "PACKET_ACTION": "FORWARD" 
            }                                                                                                                               
        }, 
        { 
        "op": "replace", 
        "path": "/ACL_RULE/TEST_DYNAMIC_TABLE|RULE_2", 
            "value": { 
                "DST_IPV6": "fc02::2/128", 
                "PRIORITY": "9998", 
                "PACKET_ACTION": "FORWARD" 
            }                                                                                                                               
        } 
    ] 

    expected_rule_1_content = ["TEST_DYNAMIC_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP:", "10.10.10.2/32"]
    expected_rule_2_content = ["TEST_DYNAMIC_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6:",  "fc02::2/128"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
        expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)
    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_remove_forward_rules(duthost):
    """Remove our two forward rules from the acl table
    As the second operation would leave the table empty, we remove the whole ACL_RULE table instead of RULE_2"""
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_RULE/TEST_DYNAMIC_TABLE|RULE_1", 
            "value":{}                                                                                                                               
        }, 
        { 
            "op": "remove", 
            "path": "/ACL_RULE", 
            "value": { }                                                                                                                               
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_removed(duthost, "RULE_1")
        expect_acl_rule_removed(duthost, "RULE_2")
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_table(duthost):
    """Remove an ACL Table Type from the duthost"""
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_TABLE/TEST_DYNAMIC_TABLE", 
            "value": { }                                                                                                                                        
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_nonexistant_table(duthost):
    """Remove an ACL Table from the duthost"""
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_TABLE/TEST_DYNAMIC_TABLE_BAD", 
            "value": { }                                                                                                                                        
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_table_type(duthost):
    """Remove an ACL Table definition from the duthost
    As we only have one ACL Table definition on """
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_TABLE_TYPE", 
            "value": { }                                                                                                                                        
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)



def test_dynamic_acl_test(rand_selected_dut):
    dynamic_acl_create_table_type(rand_selected_dut)
    dynamic_acl_create_table(rand_selected_dut)
    dynamic_acl_create_duplicate_table(rand_selected_dut)
    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_drop_rule(rand_selected_dut)
    dynamic_acl_remove_drop_rule(rand_selected_dut)
    dynamic_acl_replace_nonexistant_rule(rand_selected_dut)
    dynamic_acl_replace_rules(rand_selected_dut)
    dynamic_acl_remove_forward_rules(rand_selected_dut)
    dynamic_acl_remove_nonexistant_table(rand_selected_dut)
    dynamic_acl_remove_table(rand_selected_dut)
    dynamic_acl_remove_table_type(rand_selected_dut)

