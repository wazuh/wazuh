# Wazuh RBAC - How to create and map internal users

Wazuh RBAC allows access to Wazuh resources based on the roles and policies assigned to the users. It is an easy-to-use administration system that enables managing users' or entities' permissions to the system resources.

To learn more, see the Role-Based Access Control section.

The Wazuh platform includes an internal user database that can be used for authentication. It can also be used in addition to an external authentication system such as LDAP or Active Directory. Learn how to create users and map them with Wazuh in the sections below.

- Creating and setting a Wazuh admin user
- Creating and setting a Wazuh read-only user
- Creating an internal user and mapping it to Wazuh
- Use case: Give a user permissions to read and manage a group of agents

---

## Creating and setting a Wazuh admin user

Follow these steps to create an internal user, create a new role mapping, and give administrator permissions to the user.

1. Log into the Wazuh dashboard as administrator.
2. Click the upper-left menu icon **☰** to open the options, go to **Indexer management** > **Security**, and then **Internal users**.
3. Click **Create internal user**, provide a username and password, type `admin` as the Backend role, and click **Create**.
4. To map the user with Wazuh:
   1. Click **☰**, go to **Server management** > **Security**, and then **Roles mapping**.
   2. Click **Create Role mapping** and complete:
      - Role mapping name
      - Roles: `administrator`
      - Internal users: previously created user
   3. Click **Save role mapping**.

Ensure `run_as` is set to `true` in:

```
/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

Restart the dashboard service and clear browser cache.

---

## Creating and setting a Wazuh read-only user

1. Log into the Wazuh dashboard as administrator.
2. Go to **Indexer management** > **Security** > **Internal users**.
3. Create an internal user.
4. Go to **Roles**, create a role with:
   - Cluster permissions: `cluster_composite_ops_ro`
   - Index: `*`
   - Index permissions: `read`
   - Tenant permissions: `global_tenant` (Read only)
5. Map the user to the role.
6. Create a role mapping in **Server management** > **Security** > **Roles mapping**.
7. Save and restart dashboard.

---

## Creating an internal user and mapping it to Wazuh

1. Create an internal user.
2. Assign or create a role.
3. Map the role to the user.
4. Create a role mapping under **Server management** > **Security**.

Restart dashboard and clear cache.

---

## Use case: Give a user permissions to read and manage a group of agents

Agents example:
- Team_A: agents 001, 003
- Team_B: agents 002, 003

---

### Adding an agents group label

Edit `agent.conf`:

```xml
<agent_config>
  <labels>
    <label key="group">Team_A</label>
  </labels>
</agent_config>
```

Save configuration.

---

### Creating and mapping an internal user

Create role with DLS for alerts:

```json
{
  "bool": {
    "must": {
      "match": {
        "agent.labels.group": "Team_A"
      }
    }
  }
}
```

Create role with DLS for monitoring:

```json
{
  "bool": {
    "must": {
      "match": {
        "group": "Team_A"
      }
    }
  }
}
```

Map role to user.

---

### Mapping with Wazuh

1. Create policy with:
   - Action: `agent:read`
   - Resource: `agent:group`
   - Resource identifier: `Team_A`
2. Create role and assign policy.
3. Create role mapping with `cluster_readonly`.
4. Restart dashboard.

User will only see Team_A agents.