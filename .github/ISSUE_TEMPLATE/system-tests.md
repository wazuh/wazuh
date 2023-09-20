---
name: Release Candidate - System tests 
about: Report the results after running system tests.
title: 'Release [WAZUH VERSION] - Release Candidate [RC VERSION] - System tests'
labels: 'module/cluster, module/rbac'
assignees: ''

---

The following issue aims to run all `system tests` for the current release candidate, report the results, and open new issues for any encountered errors.

## System tests information
|                                      |                                            |
|--------------------------------------|--------------------------------------------|
| **Main release candidate issue**     |                                            |
| **Version**                          |                                            |
| **Release candidate #**              |                                            |
| **Tag**                              |                                            |
| **Previous system tests issue**      |                                            |

## Instructions
For running tests in an AWS EC2 virtual environment, you will need to meet the following requirements:

| Test | Environment | Notes|
|-----|-----|-----|
|Basic_cluster|Ubuntu 22.04.2 LTS `C5`.`XLarge` `15GB` HD|
|Big_cluster_40_agents|Ubuntu 22.04.2 LTS T3.Large `60GB` HD |
|Agentless_cluster|Ubuntu 22.04.2 LTS T3.Large 30GB HD|
|Four_manager_disconnected_node|Ubuntu 22.04.2 LTS T3.Large 30GB HD |
|One_manager_agent|Ubuntu 22.04.2 LTS T3.Large 30GB HD|
|Manager_agent|Ubuntu 22.04.2 LTS T3.Large 30GB HD|
|Enrollment_cluster|Ubuntu 22.04.2 LTS T3.Large 30GB HD|
|Basic_environment|Ubuntu 22.04.2 LTS T3.Large 30GB HD| It should be run divided in 3 parts* |

-----------
* Basic_environment:
  - part 1
  test_cluster/test_agent_key_polling/test_agent_key_polling.py
  test_multigroups/test_multigroups.py

  - part 2
  test_cluster/test_agent_files_deletion/test_agent_files_deletion.py
  test_cluster/test_agent_groups/test_agent_groups_forced_change.py

  - part 3
  test_cluster/test_agent_info_sync/agent_info_sync
-----------

These requirements should be requested from the @cicd-team.


For its execution, the installation of various packages is required, which will be detailed below.

<details><summary>Steps</summary>


```
### Updating dependencies
sudo apt update
sudo apt upgrade

### Installing git and cloning wazuh-qa project
sudo apt install git
git clone https://github.com/wazuh/wazuh-qa.git

### Installing docker
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io
sudo systemctl start docker
sudo systemctl enable docker

### Installing ansible
sudo apt install ansible

### Installing ansible-docker libraries
sudo pip3 install docker
sudo apt install python3-pip
pip install docker-py

### Restarting docker
sudo systemctl restart docker
sudo docker system prune -a -f

### Access as a root
sudo su

### Installing requirements and additional libraries
python3 -m pip install -r /home/ubuntu/wazuh-qa/requirements.txt
sudo apt install python3-pip
sudo apt install python3.10-venv
cd /home/ubuntu/wazuh-qa/deps/wazuh_testing
python3 -m pip install .

### Provisioning and executing test (It should be in the expected git branch, in this case v4.6.0-alpha1)
git checkout v4.6.0-alpha1
cd /home/ubuntu/wazuh-qa/tests/system/provisioning

### Deploy environment (in this case, four_manager_disconnected_node and branch v4.6.0-alpha1)
cd /home/ubuntu/wazuh-qa/tests/system/provisioning/four_manager_disconnected_node
sudo ansible-playbook -i inventory.yml playbook.yml --extra-vars='{"wazuh_branch":"v4.6.0-alpha1", "wazuh_qa_branch":"v4.6.0-alpha1"}'

### Run the test (In this case four_manager_disconnected_node_env )
cd /home/ubuntu/wazuh-qa/tests/system
python3 -m pytest -m four_manager_disconnected_node_env --html=report_four_manager_disconnected_node_env.html

### Destroy the environment for new tests
sudo docker stop $(sudo docker ps -q -a) && sudo docker rm $(sudo docker ps -q -a) && sudo docker system prune -a -f

```

</details>

## Test report procedure
All individual test checks must be marked as:
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| Pass | The test ran successfully. |
| Xfail | The test was expected to fail and it failed. It must be properly justified and reported in an issue.  |
| Skip | The test was not run. It must be properly justified and reported in an issue.  |
| Fail | The test failed. A new issue must be opened to evaluate and address the problem. |

All test results must have one the following statuses: 
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| :green_circle:  | All checks passed. |
| :red_circle:  | There is at least one failed check. |
| :yellow_circle:  | There is at least one expected fail or skipped test and no failures. |

Any failing test must be properly addressed with a new issue, detailing the error and the possible cause. It must be included in the `Fixes` section of the current release candidate main issue.

Any expected fail or skipped test must have an issue justifying the reason. All auditors must validate the justification for an expected fail or skipped test.

An extended report of the test results must be attached as a zip or txt. This report can be used by the auditors to dig deeper into any possible failures and details.

## Conclusions

<!--
All tests have been executed and the results can be found [here]().

|                |             |                     |                |
|----------------|-------------|---------------------|----------------|
| **Status**     | **Test**    | **Failure type**    | **Notes**      |
|                |             |                     |                |

All tests have passed and the fails have been reported or justified. I therefore conclude that this issue is finished and OK for this release candidate.
-->

## Auditors validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ] 
