"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    return

def playbook_case_test_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_case_test_1() called")

    inputs = {
        "promotion_reason": "just because",
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "phantom_pb_templates/Case test", returns the playbook_run_id
    playbook_run_id = phantom.playbook("phantom_pb_templates/Case test", container=container, inputs=inputs)

    return


def container_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("container_update_1() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "name": "Updated Container",
        "tags": None,
        "label": None,
        "owner": None,
        "status": None,
        "severity": None,
        "input_json": "{\"custom_fields\": {\"field1\": 1, \"field2\": 2}}",
        "description": None,
        "sensitivity": None,
        "container_input": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_update", parameters=parameters, name="container_update_1", callback=code_3)

    return


def code_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("code_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(f'container:  {json.dumps(container, indent=4)}')

    ################################################################################
    ## Custom Code End
    ################################################################################

    container_update_1(container=container)

    return


def code_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("code_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(f'container:  {json.dumps(container, indent=4)}')

    ################################################################################
    ## Custom Code End
    ################################################################################

    return


def code_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("code_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    id_value  = container.get("id", None)
    base_url  = phantom.build_phantom_rest_url('container')
    total_url = base_url + "/{0}".format(str(id_value))
    
    phantom.debug(f'total_url:  {total_url}')
    
    response  = phantom.requests.get(total_url, verify=False)
    jrsp = response.json()

    if response.status_code == 200:
        phantom.debug("success")
        phantom.debug(f'response:  {response}')
        phantom.debug(f'jrsp:  {jrsp}')
    else:
        phantom.error("fail")
        phantom.error(f'response:  {response}')
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    return


def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    url_formatted_string = phantom.format(
        container=container,
        template="""http://www.slashdot.org\n""",
        parameters=[
            "artifact:*.cef.app"
        ])

    parameters = []

    if url_formatted_string is not None:
        parameters.append({
            "url": url_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="url_reputation_1", assets=["test_virustotal"])

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return