"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'self_assign_all_tasks' block
    self_assign_all_tasks(container=container)

    return

def self_assign_all_tasks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("self_assign_all_tasks() called")

    input_parameter_0 = "unassign=false"

    ################################################################################
    ## Custom Code Start
    ################################################################################

    un_assign    = input_parameter_0.split("=")[1].lower()
    id_value     = container.get("id", None)
    base_url     = phantom.build_phantom_rest_url('workflow_phase')
    total_url    = base_url + "?_filter_container_id=\"{0}\"".format(str(id_value))
    current_user = str(phantom.get_effective_user())
    current_cont = id_value
    task_list    = []
    
    response  = phantom.requests.get(total_url, verify=False)
    
    if response.status_code == 200:
        
        #make sure we at least have a "data" block in our returned json
        try:
            taskId_iter = response.json()["data"]
        except KeyError:
            phantom.error("ERROR, cannot continue")
            phantom.error("Could not find the data subkey in the following json")
            phantom.error(response.text)
            return
        
        #if we have a data block find our "tasks" list
        for element_top in taskId_iter:
            if "tasks" in element_top:
                
                #in our tasks lists pull each of our id's
                for element_second in element_top["tasks"]:
                    if "id" in element_second:
                        task_list.append(int(element_second["id"]))
                
        #now that we have our task list set it to ourselves
        for task_id in task_list:
            
            if un_assign == "true":
                phantom.set_owner(container=current_cont, task_id=task_id, user="")
            else:
                phantom.set_owner(container=current_cont, task_id=task_id, user=current_user)
        
        
    else:
        phantom.error("ERROR. Could not query local REST api.")
        phantom.error(total_url)
        phantom.error(response.text)

    ################################################################################
    ## Custom Code End
    ################################################################################

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