# ADR-0001: Test virtualisation and local development approach

## Status

Proposed

## Context

DK/DK+ is a read-only metadata discovery tool that runs against installed JBoss EAP 7.3.x and 7.4.x environments.  The actual JBoss installations are created by a separate repository with its own lifecycle, and the details of its home layout are not relevant to this decision.

We need a way to:

- Run realistic integration tests on a developer laptop before any client engagement.
- Reproduce an on-premises RHEL-like target environment without requiring client access.
- Keep the DK/DK+ repository free of JBoss installer binaries and large distribution archives.
- Use the same automation style locally and in CI where possible.

## Decision

### 1. Local developer target: Vagrant + VirtualBox/VMware/KVM

The default local test target is a disposable virtual machine managed by **Vagrant**, using a RHEL-compatible box such as AlmaLinux or Rocky Linux 8.10.

- **Vagrant** is purpose-built for laptop-sized disposable VMs.
- The JBoss installation repository provides a `setup-test-jboss.sh` script that prepares the VM.
- DK/DK+ provides a `Vagrantfile` and a small wrapper that mounts the installer scripts and test fixtures.
- The VM is destroyed and recreated frequently; no persistent state is required.

### 2. Image build: Packer

Once the local setup is stable, the same provisioning scripts are used by **Packer** to produce:

- A Vagrant box for local development.
- A vSphere/VMware VM template for on-premises client environments.
- An Azure VM image in Azure Compute Gallery for cloud clients.

This keeps image creation in one tool and lets Vagrant reuse the produced box.

### 3. Infrastructure as Code: Terraform for cloud, not for local laptop VMs

**Terraform** is used for the Azure-side resources required by the operating model:

- Client-owned storage account and RBAC.
- Azure Compute Gallery images in the `service` deployment profile.
- Optional Terraform modules supplied to clients for convenience.

Terraform is **not** the default tool for creating the local developer VM.  Using Terraform with local hypervisor providers (e.g. libvirt, VirtualBox, or VMware Workstation) adds friction without benefit compared with Vagrant.

If a developer already has a local vSphere lab, a small optional `terraform/` module using the `vsphere` provider can be maintained, but it is not the primary local path.

### 4. CI target

CI uses the same `setup-test-jboss.sh` script inside a freshly provisioned VM or container.  In the short term this is a Vagrant/Packer-produced VM; in the longer term it is a Packer-built Azure Compute Gallery image triggered by the CI pipeline.

### 5. Repository/workspace boundary

The JBoss installation repository remains in its own workspace.  DK/DK+ does not depend on its internals.  The contract between the two is a small, documented set of runtime facts:

- OS version and installed packages.
- JBoss EAP major/minor version.
- Paths that the DK manifest is allowed to scan.
- Location of deployment artifacts.

## Options considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **Vagrant + VirtualBox/VMware/KVM** | Fast laptop feedback, disposable, simple synced folders, widely used | Requires local hypervisor | **Default for local** |
| **Terraform + local hypervisor provider** | Same IaC language as Azure side | Providers are less mature, slower feedback loop, more state to manage | Optional for vSphere lab only |
| **Docker/Podman container** | Very lightweight, fast CI spin-up | Does not faithfully represent a RHEL VM with systemd and custom partitioning; not chosen as primary target | May be used for quick unit-test fixtures only |
| **Full vSphere lab locally** | Exact client environment | Requires vSphere licensing and hardware; not practical for every developer | Optional path for final integration tests |

## Consequences

- Developers can `vagrant up` and run integration tests without client credentials.
- The same provisioning scripts work locally, in CI, and in client environments.
- Terraform remains focused on cloud infrastructure rather than local laptop VMs.
- Packer gives a single source of truth for base images across local and service deployment profiles.
- Keeping the installer repository separate avoids bloating the DK/DK+ repository with large JBoss distribution archives.

## Open questions

- Which local hypervisor is the team standard? VirtualBox, VMware Workstation/Fusion, or KVM/libvirt?
- Should the Packer build produce only the Vagrant box initially, or also a vSphere template?
- Does CI run the integration test inside a VM on a hosted runner, or does it need a dedicated agent with nested virtualisation?
