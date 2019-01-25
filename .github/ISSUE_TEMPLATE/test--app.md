---
name: 'Test: Wazuh App'
about: Test suite for the Wazuh App.
title: ''
labels: ''
assignees: ''

---

# Wazuh App test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

__Minimum checks for any Wazuh app. Add extra checks depending on the new features for this version.__

#### Index patterns

- [ ] Should have wazuh-alerts-3.x-* and wazuh-monitoring-3.x-*
- [ ] None of the index-patterns should be the default
- [ ] The fieldset for wazuh-alerts-3.x should have a total of 620 elements

#### API management checks

- [ ] Click on the Wazuh button on the left bar on the Kibana interface
  - [ ] Should take you to Settings and warn you there are no API credentials available
  - [ ] If it's a clean install, should appear "No API" on the top right corner
  - [ ] Should appear the index pattern on the top right corner
  - [ ] The extensions tab should be disabled
- [ ] Filling "Add API" form badly once per every form field. Should appear the appropriate error message for every wrong inserted form field
- [ ] Filling "Add API" form correctly Should connect successfully and show the data in the upper right corner
- [ ] Check manager button right after inserting API credentials. Should success and not modify anything on the fields
- [ ] Check the currently active extensions. Should be the same as the config.yml file
- [ ] Insert a new API and check everyone with the Check button Should not change the currently selected API
- [ ] Edit an API entry. The API is edited properly
- [ ] Press F5 to reload the page. Should reload properly the currently active tab (Settings)
- [ ] Go to a new tab (Management). After the health check should open the selected tab
- [ ] Delete all the existing APIs 
  - [ ] The extensions tab should be disabled
  - [ ] The top menu bar should be updated indicating that there's no API selected

#### Basic functions checks (Overview and Agents)   

- [ ] Check the initial number of checks of the health check when opening the app. Should be 4 + 1 extra for the known fields. 
- [ ] Click in Overview/Agents tab and select a proper time range
  - [ ] Should appear a loading bar and disappear after finishing loading
  - [ ] Data should appear if there are alerts
  - [ ] Visualizations should appear correctly without errors
- [ ] Click Overview/Agent -> Discover subtab. Should appear selected the wazuh-alerts-3.x index pattern only
- [ ] Click on a rule ID on the Discover tab. It should open the Ruleset detail tab for that rule ID
- [ ] Go to Dashboard subtab and activate a filter. The filter should be working
- [ ] Go again to Discover subtab. The filter should be still working and appear as a chip
- [ ] Go back to Dashboard and remove the filter. The visualizations should reload properly after deleting the filter
- [ ] Press F5 to reload the page. The filters shouldn't keep applied unless they're pinned
- [ ] Click several times the app buttons and tabs while you're on the same tab
  - [ ] Filters should persist and not disappear
  - [ ] The visualizations watchers should not lose data
- [ ] Search something on the search bar, press Enter, remove the content and press Enter again. Should always perform correctly the search and change the visualizations accordingly.
- [ ] Go to Settings and select different extensions, and then go back to Overview/Agents. The extensions configuration should keep on Overview.
- [ ] Go to Settings, select a different API with different extensions and go back to Overview/Agents. Should keep its own configuration between API selections
- [ ] Disable all the extensions, go to General and go back to Settings. The extensions should not be restored on any of the inserted APIs
- [ ] Type something and press Enter on the different Discover search bars. After pressing Enter, the search should start
- [ ] Go to Manager/Reporting prior to generating any report. Should appear a card about no reports available yet
- [ ] Click on the Report button on different tabs on Overview/Agents. After a wait, a new report should appear on Manager/Reporting
- [ ] Download a report on Management/Reporting
  - [ ] The report should be downloaded successfully
  - [ ] The report has to be related to the tab where it was generated
  - [ ] The report visualizations shouldn't have scrollbars
- [ ] Enable the Auto-Refresh functionality on Overview/Agents (Dev tools opened). The functionality should work properly
- [ ] Press F5 while having Auto-Refresh enabled Should keep working properly after refreshing the page.
- [ ] With the Auto-Refresh functionality enabled, go to Management (Dev tools opened). The functionality should stop working.
- [ ] From the Welcome screen, go to General, go back to Welcome and open again the General tab. The tab should reload properly after coming from Welcome
- [ ] Go from General to Welcome, then VirusTotal, then to Welcome, and then go again to General. Visualizations should load properly if there's actual data to show
- [ ] Enable the cluster on the Manager and open the app again. The app should load properly without errors
 - [ ] The Overview/Agents tabs should work properly with the "cluster.name" filter enabled
- [ ] Check the "Surrounding documents" buttons on Overview/Agents/Discover tabs. Both buttons should properly work
- [ ] Pin an implicit filter on a different tab and then go to the target tab. The pinned filter should become implicit, and going to another tab should make it disappear
- [ ] Add a simple filter and go to Discover, then back to Dashboard. The new filter should not be moved to the first position on the filter list


#### Filter checks (Overview and Agents)    

- [ ] "Overview/General/Dashboard -> Add `rule.level:7` -> Go to Overview/General/Discover" Filters shouldn't change
- [ ] "Overview/General/Dashboard -> Add `rule.level:7` and make it pinned -> Go to Overview/General/Discover" Filters shouldn't change
- [ ] "Overview/General/Dashboard -> Add `rule.level:7` -> Go to Overview/FIM/Dashboard" The filter "rule.level:7" is removed
- [ ] "Overview/General/Dashboard -> Add `rule.level:7` and make it pinned -> Go to Overview/FIM/Dashboard" The filter "rule.level:7" persists
- [ ] "Overview/General/Discover -> Add `rule.level:7` -> Go to Overview/FIM/Dashboard" The filter "rule.level:7" is removed
- [ ] "Overview/General/Discover -> Add `rule.level:7` and make it pinned -> Go to Overview/FIM/Dashboard" The filter "rule.level:7" persists
- [ ] "Overview/General/Discover -> Add `rule.level:7` -> Go to Overview/General/Dashboard" Filters shouldn't change
- [ ] "Overview/General/Discover -> Add `rule.level:7` and make it pinned -> Go to Overview/General/Dashboard" Filters shouldn't change
- [ ] "Overview/General/Dashboard -> Add `rule.level:7` -> Go to Agents/General/Dashboard" The filter "rule.level:7" is removed
- [ ] "Overview/General/Dashboard -> Add `rule.level:7` and make it pinned -> Go to Agents/General/Dashboard" The filter "rule.level:7" persists
- [ ] "Agents/General/Dashboard -> Add `rule.level:7` -> Go to Agents/General/Discover" Filters shouldn't change
- [ ] "Agents/General/Dashboard -> Add `rule.level:7` and make it pinned -> Go to Agents/General/Discover" Filters shouldn't change
- [ ] "Agents/General/Dashboard -> Add `rule.level:7` -> Go to Agents/FIM/Dashboard" The filter "rule.level:7" is removed
- [ ] "Agents/General/Dashboard -> Add `rule.level:7` and make it pinned -> Go to Agents/FIM/Dashboard" The filter "rule.level:7" persists
- [ ] "Agents/General/Discover -> Add `rule.level:7` -> Go to Agents/FIM/Dashboard" The filter "rule.level:7" is removed
- [ ] "Agents/General/Discover -> Add `rule.level:7` and make it pinned -> Go to Agents/FIM/Dashboard" The filter "rule.level:7" persists
- [ ] "Agents/General/Discover -> Add `rule.level:7` -> Go to Agents/General/Dashboard" Filters shouldn't change
- [ ] "Agents/General/Discover -> Add `rule.level:7` and make it pinned -> Go to Agents/General/Dashboard" Filters shouldn't change
- [ ] "Agents/General/Dashboard -> Add `rule.level:7` -> Go to Overview/General/Dashboard" The filter "rule.level:7" is removed
- [ ] "Agents/General/Dashboard -> Add `rule.level:7` and make it pinned -> Go to Overview/FIM/Dashboard" The filter "rule.level:7" persists


#### Index pattern checks  

- [ ] Go to the Settings -> Pattern tab Should not appear an incompatible index-pattern
- [ ] Open the selector on the top navbar 
- [ ] Create a new pattern and select it on Settings or the selector on the top navbar Should change successfully
- [ ] Go to Management -> Index patterns The fieldset should have a total of 567 elements
- [ ] Go to Overview/Agents Visualizations should still show data
- [ ] Go to Discover subtab The index-pattern that you selected should be present on Discover
- [ ] Change to a previous pattern with the selector or in the Settings -> Pattern tab Should change successfully
- [ ] Go to Discover subtab The selected index pattern should appear on the left  


#### Management tab checks   

- [ ] Go to Management/Status. The current Wazuh Manager version should be the same version as the installed with the current selected API 
- [ ] Go to Management/Ruleset
 - [ ] The Rules table should work properly (pagination, sorting, etc.)
 - [ ] The Decoders table should work properly (pagination, sorting, etc.)
 - [ ] The search should work correctly applying different filters
 - [ ] On Ruleset, open a rule or decoder and click on the filters Should take you back to the list and apply the filter properly
 - [ ] Remove the applied rule or decoder filter Should update the table and not apply the filter indeed
- [ ] Go to Management/Groups
 - [ ] Searching agents, click agents and files should work correctly
 - [ ] All the tables from the tab (agents, files, groups) should work properly (pagination, sorting, etc.)
 - [ ] Edit group configuration
 - [ ] Create/remove a group
 - [ ] Add/remove agents
- [ ] Go to Management/Logs
 - [ ] The Logs table should work properly (pagination, sorting, etc.)
 - [ ] The search should work correctly
 - [ ] The "Play real-time" button should work properly and update the table every few seconds
- [ ] Go to Management/Monitoring without cluster
 - [ ] Should appear a warning about not having the cluster-enabled, and don't show anything else
 - [ ] Enable the cluster and go back again to Monitoring. Should appear the main Monitoring tab with visualizations and cluster data
 - [ ] Navigate through the different Monitoring tabs Everything should work properly

#### Agents tab checks    

- [ ] Go to Agents Preview The agent's table should work properly (pagination, sorting, etc.)
- [ ] Check the different filters (node, agent version, OS, etc) All the filters should work properly and show the correct information
- [ ] Disable the cluster and check the node filter It should not appear along with the other filters since the cluster is disabled
- [ ] Go to a single agent The scrolling search bar from the upper right corner should work properly
- [ ] Change to a different agent or manager with the autocomplete component The filters should update properly to the new location
- [ ] Reload (F5) the page while on the Configuration tab The agent name, ID and status should be reloaded again
- [ ] Reload (F5) the page while on the Inventory tab Everything should work properly and the tab should appear
- [ ] From Welcome, go to General, go back to Welcome, change agent with autocomplete and open General again Should not have multiple agent.id filters applied
- [ ] On the Agent tab, go to PM, then go to Configuration and then go back to FIM The filters should change correctly according to the expected behavior (pinned/not pinned/implicit filter)
- [ ] Add some agent group configuration to the default group.  The Configuration tab in Agents should say SYNCHRONIZED


#### Dev tools checks 
   
- [ ] Tro to execute GET API calls The output should be the expected
- [ ] Try to execute the /agents/:agent_id/key call The output should be Forbidden
- [ ] Try to execute PUT, POST or DELETE calls The output should be "Valid method: GET"
- [ ] Try to combine in-line with JSON-like parameters Should apply both parameters and if there are duplicates, apply first the in-line one
- [ ] Open the tab when the first line is empty or a comment Should try to execute the first block with a valid API request
- [ ] Leave only a comment on the editor pane and open again the tab Should get a "Welcome!" message
- [ ] Empty the editor pane and open again the tab The editor pane should be filled with the basic example template
- [ ] Try to execute the first API call having several blank lines above The play button should apprear and let the user execute the query


#### Miscellaneous checks  

- [ ] "Insert a secured API in Settings and check it
(/var/ossec/api/scrips/configure_api.sh)" Should connect successfully, and not fail the form when inserting it
- [ ] Delete some files from a group configuration The Content table of a group should show correctly the remaining files for each of the available groups
- [ ] Modify the config.yml checks. Uncomment the default ones and change the values After restarting the Kibana service, should apply the new checks configuration and you shouldn't be able to see the pattern selector
- [ ] The new configuration should be available on Settings > Configuration
- [ ] "Modify the IP selector on config.yml
(using false or 0)" After restarting the Kibana service, should apply the new configuration
- [ ] "Cat the logs file
(/usr/share/kibana/plugins/wazuh-logs/wazuhapp.log)" The file should be registering the logs, for example after restarting Kibana
- [ ] The last 20 logs should appear con Settings > Logs
- [ ] Download some tables using the CSV formatted button Should work properly and download a file to your computer
- [ ] The max amount of data that should download is 45k entries, even if there's more data to download
- [ ] Enable some of the default-false extensions -> Go to Overview and open it -> Go again to Settings and enable another one (different) -> Go to Overview The two extensions should be enabled now
- [ ] Open the Settings > Logs tab It should load the logs properly
- [ ] If you click on the refresh button, it should reload them properly  


#### Breaking app checks  

- [ ] Delete the index-patterns and restart the Kibana server Should re-create the default index-patterns and recover properly
- [ ] Delete the default wazuh-alerts index-pattern and create a new one (with a different ID), and restart Kibana The app should reload properly the new pattern and update its visualizations
- [ ] Delete the .kibana index with a CURL command and restart Kibana Should have again the default two index patterns
- [ ] Delete the .wazuh index with a CURL command and restart Kibana Should warn you again to insert the API credentials
- [ ] Delete the .wazuh-version index with a CURL command and restart Kibana Nothing weird should happen, and the version card on Settings -> About should show information
- [ ] "Create a new index-pattern on the Management tab
- [ ] Assign that index-pattern to the app
- [ ] Delete the index-pattern
- [ ] Restart the Kibana server" The app should recover properly after restarting
- [ ] Select the wazuh-alerts* index pattern on the app, create a wazuh-al* index pattern and select it on the app, and finally go again to Management -> Index patterns
- [ ] After installing the app, insert an API and reinstall the app. There should not be any errors when reinstalling an app with an existing API on the indices
- [ ] Add a custom index pattern (using a custom template) Everything should work properly and the app should use the new pattern and template
- [ ] Change the number of replicas on the indices after those being generated Using the curl call for _cat/indices, the replicas settings should be applied after restarting Kibana
