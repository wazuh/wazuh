---
name: Ansible, Puppet, Docker, Kubernetes and Bosh draft releases
about: Ansible, Puppet, Docker, Kubernetes and Bosh draft releases 
title: 'Ansible, Puppet, Docker, Kubernetes and Bosh [WAZUH VERSION] draft releases'
labels: 'cicd'
assignees: ''

---
# wazuh-ansible

### Pre-release tasks
- https://github.com/wazuh/wazuh-ansible/issues/ISSUE_NUMBER
  - [] Bump PR from release branch to [WAZUH MAJOR]
  - [] Test [WAZUH MAJOR] branch
### Post-release tasks
- https://github.com/wazuh/wazuh-ansible/issues/ISSUE_NUMBER
  - [] Create draft release and [WAZUH VERSION] tag 
  - [] Merge [WAZUH MAJOR] into stable
  - [] Merge [WAZUH MAJOR] into master
  - [] Update version in wazuh/wazuh-documentary

# wazuh-puppet

### Pre-release tasks
- https://github.com/wazuh/wazuh-puppet/issues/ISSUE_NUMBER
  - [] Bump PR from release branch to [WAZUH MAJOR]
  - [] Test [WAZUH MAJOR] branch

### Post-release tasks
- https://github.com/wazuh/wazuh-puppet/issues/ISSUE_NUMBER
  - [] Create [WAZUH VERSION] tag 
  - [] Create draft release 
  - [] Publish draft release 
  - [] Upload release to forge
  - [] Merge [WAZUH MAJOR] into stable
  - [] Merge [WAZUH MAJOR] into master
  - [] Update version in wazuh/wazuh-documentary

# wazuh-docker

### Pre-release tasks
- https://github.com/wazuh/wazuh-docker/issues/ISSUE_NUMBER
  - [] Bump PR from release branch to [WAZUH MAJOR]
  - [] Test [WAZUH MAJOR] branch
### Post-release tasks
- https://github.com/wazuh/wazuh-docker/issues/ISSUE_NUMBER
  - [] Create [WAZUH VERSION] tag
  - [] Create draft release
  - [] Upload docker images to DockerHub
  - [] Publish draft release 
  - [] Merge [WAZUH MAJOR] into stable
  - [] Merge [WAZUH MAJOR] into master
  - [] Update version in wazuh/wazuh-documentary
  - [] Update Compatibility Matrix in DockerHub repositories

# wazuh-kubernetes

### Pre-release tasks
- https://github.com/wazuh/wazuh-kubernetes/issues/ISSUE_NUMBER
  - [] Bump PR from release branch to [WAZUH MAJOR]
  - [] Test [WAZUH MAJOR] branch
### Post-release tasks
- https://github.com/wazuh/wazuh-kubernetes/issues/ISSUE_NUMBER
  - [] Create [WAZUH VERSION] tag 
  - [] Create draft release 
  - [] Publish draft release 
  - [] Merge [WAZUH MAJOR] into stable
  - [] Merge [WAZUH MAJOR] into master
  - [] Update version in wazuh/wazuh-documentary

# wazuh-bosh

### Pre-release tasks
- https://github.com/wazuh/wazuh-bosh/issues/ISSUE_NUMBER
  - [] Bump PR from release branch to [WAZUH MAJOR]
  - [] Test [WAZUH MAJOR] branch
### Post-release tasks
- https://github.com/wazuh/wazuh-bosh/issues/ISSUE_NUMBER
  - [] Create draft release and [WAZUH VERSION] tag 
  - [] Merge [WAZUH MAJOR] into stable
  - [] Merge [WAZUH MAJOR] into master
  - [] Update version in wazuh/wazuh-documentary


## Auditors validation

In order to close and proceed with release or the next candidate version, the following auditors must give the green light to this RC.

- [ ] @santiago-bassett 
- [ ] @alberpilot 
- [ ] @okynos 
- [ ] @rauldpm 
