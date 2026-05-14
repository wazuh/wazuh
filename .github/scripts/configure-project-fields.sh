#!/bin/bash
# Script to configure GitHub Project fields for an issue
# Usage: configure-project-fields.sh <issue_number> <release> <stage>

set -e

ISSUE_NUMBER=$1
RELEASE=$2
STAGE=$3

if [[ -z "$ISSUE_NUMBER" || -z "$RELEASE" || -z "$STAGE" ]]; then
  echo "Usage: $0 <issue_number> <release> <stage>"
  exit 1
fi

REPO="wazuh/wazuh"
PROJECT_NUMBER=86  # XDR+SIEM/Agent team project number

echo "Configuring fields for issue #$ISSUE_NUMBER in project..."

# Determine release type based on version
if [[ "$RELEASE" =~ \.0\.0$ ]]; then
  RELEASE_TYPE="Major"
elif [[ "$RELEASE" =~ \.0$ ]]; then
  RELEASE_TYPE="Minor"
else
  RELEASE_TYPE="Patch"
fi

echo "Release: $RELEASE"
echo "Stage: $STAGE"
echo "Release Type: $RELEASE_TYPE"

# Get issue node ID and project item ID
echo ""
echo "Fetching issue and project data..."
ISSUE_DATA=$(gh api graphql -f query='
  query($owner: String!, $repo: String!, $number: Int!) {
    repository(owner: $owner, name: $repo) {
      issue(number: $number) {
        id
        projectItems(first: 10) {
          nodes {
            id
            project {
              ... on ProjectV2 {
                id
                number
                title
              }
            }
          }
        }
      }
    }
  }' -f owner='wazuh' -f repo='wazuh' -F number=$ISSUE_NUMBER)

# Find the project item that matches our project number
PROJECT_ID=$(echo "$ISSUE_DATA" | jq -r ".data.repository.issue.projectItems.nodes[] | select(.project.number==$PROJECT_NUMBER) | .project.id")
ITEM_ID=$(echo "$ISSUE_DATA" | jq -r ".data.repository.issue.projectItems.nodes[] | select(.project.number==$PROJECT_NUMBER) | .id")

if [[ -z "$ITEM_ID" || "$ITEM_ID" == "null" ]]; then
  echo "Error: Issue #$ISSUE_NUMBER not found in project #$PROJECT_NUMBER"
  echo "Make sure the issue was created with --project flag"
  exit 1
fi

echo "✓ Issue found in project"
echo "Project ID: $PROJECT_ID"
echo "Item ID: $ITEM_ID"

# Get field IDs from the project
FIELDS_DATA=$(gh api graphql -f query='
  query($org: String!, $number: Int!) {
    organization(login: $org) {
      projectV2(number: $number) {
        fields(first: 50) {
          nodes {
            ... on ProjectV2Field {
              id
              name
            }
            ... on ProjectV2SingleSelectField {
              id
              name
              options {
                id
                name
              }
            }
          }
        }
      }
    }
  }' -f org='wazuh' -F number=$PROJECT_NUMBER)

# Extract field IDs
STATUS_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Status") | .id')
OBJECTIVE_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Objective") | .id')
PRIORITY_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Priority") | .id')
SIZE_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Size") | .id')
RELEASE_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Release") | .id')
STAGE_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Stage") | .id')
RELEASE_TYPE_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Release type") | .id')
CHANGELOG_FIELD_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Changelog") | .id')

# Extract option IDs for single-select fields
STATUS_BACKLOG_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Status") | .options[] | select(.name=="Backlog") | .id')
PRIORITY_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Priority") | .options[] | select(.name=="Urgent") | .id')
SIZE_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Size") | .options[] | select(.name=="Small") | .id')
CHANGELOG_DONE_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Changelog") | .options[] | select(.name=="Done") | .id')

# Find Stage option ID based on the provided stage value
STAGE_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r --arg stage "$STAGE" '.data.organization.projectV2.fields.nodes[] | select(.name=="Stage") | .options[] | select(.name==$stage) | .id')

# Find Release Type option ID based on version
if [[ "$RELEASE_TYPE" == "Major" ]]; then
  RELEASE_TYPE_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Release type") | .options[] | select(.name=="Major") | .id')
elif [[ "$RELEASE_TYPE" == "Minor" ]]; then
  RELEASE_TYPE_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Release type") | .options[] | select(.name=="Minor") | .id')
else
  RELEASE_TYPE_OPTION_ID=$(echo "$FIELDS_DATA" | jq -r '.data.organization.projectV2.fields.nodes[] | select(.name=="Release type") | .options[] | select(.name=="Patch") | .id')
fi

# Function to update a single-select field
update_field() {
  local field_id=$1
  local option_id=$2
  local field_name=$3

  if [[ -z "$field_id" || -z "$option_id" ]]; then
    echo "Warning: Could not find field or option for $field_name"
    return 1
  fi

  gh api graphql -f query='
    mutation($project: ID!, $item: ID!, $field: ID!, $value: String!) {
      updateProjectV2ItemFieldValue(
        input: {
          projectId: $project
          itemId: $item
          fieldId: $field
          value: {
            singleSelectOptionId: $value
          }
        }
      ) {
        projectV2Item {
          id
        }
      }
    }' -f project="$PROJECT_ID" -f item="$ITEM_ID" -f field="$field_id" -f value="$option_id" > /dev/null

  echo "✓ Set $field_name"
}

# Function to update text field
update_text_field() {
  local field_id=$1
  local text_value=$2
  local field_name=$3

  if [[ -z "$field_id" ]]; then
    echo "Warning: Could not find field for $field_name"
    return 1
  fi

  gh api graphql -f query='
    mutation($project: ID!, $item: ID!, $field: ID!, $value: String!) {
      updateProjectV2ItemFieldValue(
        input: {
          projectId: $project
          itemId: $item
          fieldId: $field
          value: {
            text: $value
          }
        }
      ) {
        projectV2Item {
          id
        }
      }
    }' -f project="$PROJECT_ID" -f item="$ITEM_ID" -f field="$field_id" -f value="$text_value" > /dev/null

  echo "✓ Set $field_name = $text_value"
}

# Update all fields
echo ""
echo "Updating project fields..."
update_field "$STATUS_FIELD_ID" "$STATUS_BACKLOG_OPTION_ID" "Status"
update_text_field "$OBJECTIVE_FIELD_ID" "Release testing" "Objective"
update_field "$PRIORITY_FIELD_ID" "$PRIORITY_OPTION_ID" "Priority"
update_field "$SIZE_FIELD_ID" "$SIZE_OPTION_ID" "Size"
update_text_field "$RELEASE_FIELD_ID" "$RELEASE" "Release"
update_field "$STAGE_FIELD_ID" "$STAGE_OPTION_ID" "Stage"
update_field "$RELEASE_TYPE_FIELD_ID" "$RELEASE_TYPE_OPTION_ID" "Release type"
update_field "$CHANGELOG_FIELD_ID" "$CHANGELOG_DONE_OPTION_ID" "Changelog"

echo ""
echo "✅ Issue #$ISSUE_NUMBER successfully configured in project"
