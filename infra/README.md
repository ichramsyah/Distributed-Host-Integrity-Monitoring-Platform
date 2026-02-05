# 🏗️ DHIMP - Infrastructure & Deployment

This directory contains the **Ansible** automation scripts used to deploy the Backend and Agent components to production servers.

## 📖 Overview

The deployment strategy focuses on **immutable infrastructure patterns** where possible. We use Ansible to orchestrate the update process, ensuring consistency across all monitored nodes.

## 📂 File Structure

```bash
infra/
├── deploy-backend.yml    # Main Ansible Playbook
└── inventory.ini         # Server Inventory (IPs & Groups)
```

## 🚀 Deployment Workflow

The `deploy-backend.yml` playbook performs the following "Zero-To-Hero" sequence:

1.  **Git Pull**: Fetches the latest code from the `main` branch.
2.  **Dependency Install**: Updates the Python virtual environment (`venv`).
3.  **Database Migration**: Runs `python manage.py migrate` to apply schema changes.
4.  **Container Reset**:
    -   Stops running containers.
    -   Prunes unused Docker objects (Deep Clean).
    -   Re-builds and starts the services (`docker compose up --build`).

## 🛠️ Configuration

### Inventory Setup (`inventory.ini`)

Define your server groups and connection details here.

```ini
[backend_servers]
prod-app-01 ansible_host=10.0.10.21
prod-app-02 ansible_host=10.0.10.22

[all:vars]
ansible_user=deploy_runner
ansible_ssh_private_key_file=~/.ssh/prod_deploy_key.pem
```

## ⚡ Usage

To deploy the latest version to all backend servers:

```bash
# syntax: ansible-playbook -i <inventory> <playbook>
ansible-playbook -i inventory.ini deploy-backend.yml
```

## ⚠️ Notes

-   **SSH Access**: Ensure the machine running Ansible has SSH access to the target servers via the key specified in `inventory.ini`.
-   **Docker Rights**: The `ansible_user` must be part of the `docker` group on the target servers to execute docker commands without sudo.
