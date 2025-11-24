"""
This playbook proactively blocks high impact indicators ingested from PhishMe. It was constructed for the Phantom Tech Session held on 04/07/2017 with PhishMe.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_2' block
    decision_2(container=container)

    return

@phantom.playbook_block()
def set_severity_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_6() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    return


@phantom.playbook_block()
def filter_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_11() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        name="filter_11:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_12() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        name="filter_12:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_10() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.destinationAddress", "!=", ""]
        ],
        name="filter_10:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_13() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHashMd5", "!=", ""]
        ],
        name="filter_13:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def ip_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.destinationAddress", "!=", ""]
        ],
        conditions_dps=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.destinationAddress", "!=", ""]
        ],
        name="ip_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.severity", "==", "high"]
        ],
        conditions_dps=[
            ["artifact:*.severity", "==", "high"]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_report_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    filter_10(action=action, success=success, container=container, results=results, handle=handle)
    filter_11(action=action, success=success, container=container, results=results, handle=handle)
    filter_12(action=action, success=success, container=container, results=results, handle=handle)
    filter_13(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_severity_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_7() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    return


@phantom.playbook_block()
def set_severity_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_8() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    return


@phantom.playbook_block()
def domain_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        conditions_dps=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.destinationDnsDomain", "!=", ""]
        ],
        name="domain_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_domain_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def block_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_url_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_url_filter = phantom.collect2(container=container, datapath=["filtered-data:url_filter:condition_1:artifact:*.cef.requestURL","filtered-data:url_filter:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'block_url_1' call
    for filtered_artifact_0_item_url_filter in filtered_artifact_0_data_url_filter:
        if filtered_artifact_0_item_url_filter[0] is not None:
            parameters.append({
                "url": filtered_artifact_0_item_url_filter[0],
                "vsys": "",
                "sec_policy": "",
                "context": {'artifact_id': filtered_artifact_0_item_url_filter[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block url", parameters=parameters, name="block_url_1", assets=["pafw-fake"], callback=format_4)

    return


@phantom.playbook_block()
def block_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_domain_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_domain_filter = phantom.collect2(container=container, datapath=["filtered-data:domain_filter:condition_1:artifact:*.cef.destinationDnsDomain","filtered-data:domain_filter:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'block_domain_1' call
    for filtered_artifact_0_item_domain_filter in filtered_artifact_0_data_domain_filter:
        if filtered_artifact_0_item_domain_filter[0] is not None:
            parameters.append({
                "domain": filtered_artifact_0_item_domain_filter[0],
                "disable_safeguards": "",
                "context": {'artifact_id': filtered_artifact_0_item_domain_filter[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block domain", parameters=parameters, name="block_domain_1", assets=["cu-fake"], callback=format_3)

    return


@phantom.playbook_block()
def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_8() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.severity", "==", "high"]
        ],
        conditions_dps=[
            ["artifact:*.severity", "==", "high"]
        ],
        name="filter_8:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        domain_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        url_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def block_hash_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_hash_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    file_reputation_2_result_data = phantom.collect2(container=container, datapath=["file_reputation_2:action_result.parameter.hash","file_reputation_2:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'block_hash_3' call
    for file_reputation_2_result_item in file_reputation_2_result_data:
        if file_reputation_2_result_item[0] is not None:
            parameters.append({
                "hash": file_reputation_2_result_item[0],
                "comment": "",
                "context": {'artifact_id': file_reputation_2_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block hash", parameters=parameters, name="block_hash_3", assets=["cbr-fake"], callback=format_5)

    return


@phantom.playbook_block()
def url_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.requestURL", "!=", ""]
        ],
        conditions_dps=[
            ["filtered-data:filter_8:condition_1:artifact:*.cef.requestURL", "!=", ""]
        ],
        name="url_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_url_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_10 = phantom.collect2(container=container, datapath=["filtered-data:filter_10:condition_1:artifact:*.cef.destinationAddress","filtered-data:filter_10:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation_1' call
    for filtered_artifact_0_item_filter_10 in filtered_artifact_0_data_filter_10:
        if filtered_artifact_0_item_filter_10[0] is not None:
            parameters.append({
                "ip": filtered_artifact_0_item_filter_10[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_10[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_1", assets=["vt"], callback=decision_9)

    return


@phantom.playbook_block()
def file_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_reputation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_9 = phantom.collect2(container=container, datapath=["filtered-data:filter_9:condition_1:artifact:*.cef.fileHashMd5","filtered-data:filter_9:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'file_reputation_2' call
    for filtered_artifact_0_item_filter_9 in filtered_artifact_0_data_filter_9:
        if filtered_artifact_0_item_filter_9[0] is not None:
            parameters.append({
                "hash": filtered_artifact_0_item_filter_9[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_9[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_reputation_2", assets=["vt"], callback=filter_5)

    return


@phantom.playbook_block()
def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("domain_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_11 = phantom.collect2(container=container, datapath=["filtered-data:filter_11:condition_1:artifact:*.cef.destinationDnsDomain","filtered-data:filter_11:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'domain_reputation_1' call
    for filtered_artifact_0_item_filter_11 in filtered_artifact_0_data_filter_11:
        if filtered_artifact_0_item_filter_11[0] is not None:
            parameters.append({
                "domain": filtered_artifact_0_item_filter_11[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_11[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="domain_reputation_1", assets=["vt"], callback=decision_8)

    return


@phantom.playbook_block()
def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_12 = phantom.collect2(container=container, datapath=["filtered-data:filter_12:condition_1:artifact:*.cef.requestURL","filtered-data:filter_12:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'url_reputation_1' call
    for filtered_artifact_0_item_filter_12 in filtered_artifact_0_data_filter_12:
        if filtered_artifact_0_item_filter_12[0] is not None:
            parameters.append({
                "url": filtered_artifact_0_item_filter_12[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_12[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="url_reputation_1", assets=["vt"], callback=decision_7)

    return


@phantom.playbook_block()
def set_severity_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_9() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    return


@phantom.playbook_block()
def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_5() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["file_reputation_2:summary.total_positives", ">=", 10]
        ],
        conditions_dps=[
            ["file_reputation_2:summary.total_positives", ">=", 10]
        ],
        name="filter_5:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        hunt_file_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def filter_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_9() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashMd5", "!=", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.fileHashMd5", "!=", ""]
        ],
        name="filter_9:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("block_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_ip_filter = phantom.collect2(container=container, datapath=["filtered-data:ip_filter:condition_1:artifact:*.cef.destinationAddress","filtered-data:ip_filter:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'block_ip_1' call
    for filtered_artifact_0_item_ip_filter in filtered_artifact_0_data_ip_filter:
        if filtered_artifact_0_item_ip_filter[0] is not None:
            parameters.append({
                "ip": filtered_artifact_0_item_ip_filter[0],
                "vsys": "",
                "is_source_address": "",
                "context": {'artifact_id': filtered_artifact_0_item_ip_filter[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("block ip", parameters=parameters, name="block_ip_1", assets=["pafw-fake"], callback=format_2)

    return


@phantom.playbook_block()
def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_8() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["domain_reputation_1:summary.total_positives", ">=", 10]
        ],
        conditions_dps=[
            ["domain_reputation_1:summary.total_positives", ">=", 10]
        ],
        name="decision_8:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_8(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_9() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ip_reputation_1:summary.total_positives", ">=", 10]
        ],
        conditions_dps=[
            ["ip_reputation_1:summary.total_positives", ">=", 10]
        ],
        name="decision_9:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_9(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_7() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["url_reputation_1:summary.total_positives", ">=", 10]
        ],
        conditions_dps=[
            ["url_reputation_1:summary.total_positives", ">=", 10]
        ],
        name="decision_7:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_7(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("file_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_13 = phantom.collect2(container=container, datapath=["filtered-data:filter_13:condition_1:artifact:*.cef.fileHash","filtered-data:filter_13:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'file_reputation_1' call
    for filtered_artifact_0_item_filter_13 in filtered_artifact_0_data_filter_13:
        if filtered_artifact_0_item_filter_13[0] is not None:
            parameters.append({
                "hash": filtered_artifact_0_item_filter_13[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_13[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_reputation_1", assets=["vt"], callback=decision_6)

    return


@phantom.playbook_block()
def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_6() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["file_reputation_1:summary.total_positives", ">=", 10]
        ],
        conditions_dps=[
            ["file_reputation_1:summary.total_positives", ">=", 10]
        ],
        name="decision_6:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_6(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def join_set_severity_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_set_severity_3() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_set_severity_3_called"):
        return

    if phantom.completed(action_names=["update_ticket_7"]):
        # save the state that the joined function has now been called
        phantom.save_block_result(key="join_set_severity_3_called", value="set_severity_3")

        # call connected block "set_severity_3"
        set_severity_3(container=container, handle=handle)

    return


@phantom.playbook_block()
def set_severity_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    set_status_4(container=container)

    return


@phantom.playbook_block()
def set_status_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_status_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_report_2:action_result"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    create_ticket_5(container=container)

    return


@phantom.playbook_block()
def create_ticket_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_ticket_5() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_report_2_result_data = phantom.collect2(container=container, datapath=["get_report_2:action_result.parameter.threat_id","get_report_2:action_result.parameter.context.artifact_id"], action_results=results)
    format_1 = phantom.get_format_data(name="format_1")

    parameters = []

    # build parameters list for 'create_ticket_5' call
    for get_report_2_result_item in get_report_2_result_data:
        parameters.append({
            "table": "incident",
            "fields": "",
            "vault_id": "",
            "description": format_1,
            "short_description": get_report_2_result_item[0],
            "context": {'artifact_id': get_report_2_result_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create ticket", parameters=parameters, name="create_ticket_5", assets=["snow-fake"], callback=create_ticket_5_callback)

    return


@phantom.playbook_block()
def create_ticket_5_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_ticket_5_callback() called")

    
    filter_8(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_9(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def get_report_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_report_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.phishmeThreatId","artifact:*.id"])

    parameters = []

    # build parameters list for 'get_report_2' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "threat_id": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get report", parameters=parameters, name="get_report_2", assets=["cofense-fake"], callback=format_1)

    return


@phantom.playbook_block()
def update_ticket_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_ticket_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_ticket_5_result_data = phantom.collect2(container=container, datapath=["create_ticket_5:action_result.summary.created_ticket_id","create_ticket_5:action_result.parameter.table","create_ticket_5:action_result.parameter.context.artifact_id"], action_results=results)
    format_2 = phantom.get_format_data(name="format_2")

    parameters = []

    # build parameters list for 'update_ticket_3' call
    for create_ticket_5_result_item in create_ticket_5_result_data:
        if create_ticket_5_result_item[0] is not None:
            parameters.append({
                "id": create_ticket_5_result_item[0],
                "table": create_ticket_5_result_item[1],
                "fields": format_2,
                "vault_id": "",
                "context": {'artifact_id': create_ticket_5_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update ticket", parameters=parameters, name="update_ticket_3", assets=["snow-fake"], callback=join_set_severity_3)

    return


@phantom.playbook_block()
def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_2() called")

    template = """{{\"work_notes\": \"The following source IPs connected with dst: {0}\\n\\nsrc: {1}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_ip_1:action_result.parameter.ip",
        "filtered-data:ip_filter:condition_1:artifact:*.cef.sourceAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    update_ticket_3(container=container)

    return


@phantom.playbook_block()
def update_ticket_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_ticket_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_ticket_5_result_data = phantom.collect2(container=container, datapath=["create_ticket_5:action_result.summary.created_ticket_id","create_ticket_5:action_result.parameter.table","create_ticket_5:action_result.parameter.context.artifact_id"], action_results=results)
    format_3 = phantom.get_format_data(name="format_3")

    parameters = []

    # build parameters list for 'update_ticket_4' call
    for create_ticket_5_result_item in create_ticket_5_result_data:
        if create_ticket_5_result_item[0] is not None:
            parameters.append({
                "id": create_ticket_5_result_item[0],
                "table": create_ticket_5_result_item[1],
                "fields": format_3,
                "vault_id": "",
                "context": {'artifact_id': create_ticket_5_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update ticket", parameters=parameters, name="update_ticket_4", assets=["snow-fake"], callback=join_set_severity_3)

    return


@phantom.playbook_block()
def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_3() called")

    template = """{{\"work_notes\": \"The following source IPs:\\n{1}\\n\\nconnected with destination domain:\\n{0}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_domain_1:action_result.parameter.domain",
        "filtered-data:domain_filter:condition_1:artifact:*.cef.sourceAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    update_ticket_4(container=container)

    return


@phantom.playbook_block()
def format_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_4() called")

    template = """{{\"work_notes\": \"The following source IPs:\\n{1}\\n\\nconnected with the URL:\\n{0}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_url_1:action_result.parameter.url",
        "filtered-data:url_filter:condition_1:artifact:*.cef.sourceAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_4")

    update_ticket_5(container=container)

    return


@phantom.playbook_block()
def update_ticket_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_ticket_5() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_ticket_5_result_data = phantom.collect2(container=container, datapath=["create_ticket_5:action_result.summary.created_ticket_id","create_ticket_5:action_result.parameter.table","create_ticket_5:action_result.parameter.context.artifact_id"], action_results=results)
    format_4 = phantom.get_format_data(name="format_4")

    parameters = []

    # build parameters list for 'update_ticket_5' call
    for create_ticket_5_result_item in create_ticket_5_result_data:
        if create_ticket_5_result_item[0] is not None:
            parameters.append({
                "id": create_ticket_5_result_item[0],
                "table": create_ticket_5_result_item[1],
                "fields": format_4,
                "vault_id": "",
                "context": {'artifact_id': create_ticket_5_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update ticket", parameters=parameters, name="update_ticket_5", assets=["snow-fake"], callback=join_set_severity_3)

    return


@phantom.playbook_block()
def update_ticket_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_ticket_6() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_ticket_5_result_data = phantom.collect2(container=container, datapath=["create_ticket_5:action_result.summary.created_ticket_id","create_ticket_5:action_result.parameter.table","create_ticket_5:action_result.parameter.context.artifact_id"], action_results=results)
    format_5 = phantom.get_format_data(name="format_5")

    parameters = []

    # build parameters list for 'update_ticket_6' call
    for create_ticket_5_result_item in create_ticket_5_result_data:
        if create_ticket_5_result_item[0] is not None:
            parameters.append({
                "id": create_ticket_5_result_item[0],
                "table": create_ticket_5_result_item[1],
                "fields": format_5,
                "vault_id": "",
                "context": {'artifact_id': create_ticket_5_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update ticket", parameters=parameters, name="update_ticket_6", assets=["snow-fake"], callback=join_set_severity_3)

    return


@phantom.playbook_block()
def update_ticket_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_ticket_7() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_ticket_5_result_data = phantom.collect2(container=container, datapath=["create_ticket_5:action_result.summary.created_ticket_id","create_ticket_5:action_result.parameter.table","create_ticket_5:action_result.parameter.context.artifact_id"], action_results=results)
    format_6 = phantom.get_format_data(name="format_6")

    parameters = []

    # build parameters list for 'update_ticket_7' call
    for create_ticket_5_result_item in create_ticket_5_result_data:
        if create_ticket_5_result_item[0] is not None:
            parameters.append({
                "id": create_ticket_5_result_item[0],
                "table": create_ticket_5_result_item[1],
                "fields": format_6,
                "vault_id": "",
                "context": {'artifact_id': create_ticket_5_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update ticket", parameters=parameters, name="update_ticket_7", assets=["snow-fake"], callback=join_set_severity_3)

    return


@phantom.playbook_block()
def hunt_file_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("hunt_file_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    file_reputation_2_result_data = phantom.collect2(container=container, datapath=["file_reputation_2:action_result.parameter.hash","file_reputation_2:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'hunt_file_3' call
    for file_reputation_2_result_item in file_reputation_2_result_data:
        if file_reputation_2_result_item[0] is not None:
            parameters.append({
                "hash": file_reputation_2_result_item[0],
                "type": "binary",
                "range": "",
                "context": {'artifact_id': file_reputation_2_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("hunt file", parameters=parameters, name="hunt_file_3", assets=["cbr-fake"], callback=format_6)

    return


@phantom.playbook_block()
def format_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_6() called")

    template = """{{\"work_notes\": \"The malicious filehash {0} was found on the following hosts:\\n{1}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_file_3:action_result.parameter.hash",
        "hunt_file_3:action_result.data.*.process.results.*.hostname"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_6")

    update_ticket_7(container=container)

    return


@phantom.playbook_block()
def format_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_5() called")

    template = """{{\"work_notes\": \"The following source IPs:\\n{1}\\n\\nwere detected with the following fileHash:\\n{0}\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "block_hash_3:action_result.parameter.hash",
        "artifact:*.cef.sourceAddress"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_5")

    update_ticket_6(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return