# CAPSlock

**CAPSlock** is an offline Conditional Access (CA) analysis tool built on top of a `roadrecon` database.  
It helps defenders, auditors, and red teams understand **how Conditional Access policies actually behave**, not just how they are configured.

Instead of answering *“what policies exist?”*, CAPSlock focuses on:

- Who is actually covered
- Under what sign-in conditions
- Where enforcement gaps or bypass scenarios exist

CAPSlock is read-only and safe to run against production tenants.

---
## Requirements and Installation 

### Requirements
1. Python3
2. [ROADtools](https://github.com/dirkjanm/ROADtools)

### Installation
1. Create virtual environment. (I prefer `venv`, but `uv` and other solutions work as well)

```bash
python3 -m venv <virtual-environemtn-name>

#Activate virtual environment
source <path-to-environment>/bin/activate
```

2. Install Dependancies

```bash
pip install -r requirements.txt
```

3. (Optional) Install Web GUI Dependencies

```bash
pip install -r web-gui/requirements.txt
```

---

## get-policies

### What it does

`get-policies` lists **all Conditional Access policies that target a specific user**, based on policy scoping and conditions stored in the offline Entra / Conditional Access data.

Rather than answering *“what policies exist in the tenant?”*, this command answers:

> **Which policies actually apply to this user, and why?**

Each policy is evaluated against the user’s direct inclusion, group membership, and role-based targeting. The output clearly shows whether a policy:
- Applies
- Is excluded
- Or does not target the user at all

For each policy, CAPSlock explains the reasoning and summarizes the relevant conditions in a human-readable format.

### Syntax

```bash
python3 CAPSlock.py get-policies -u <userprincipalname> [options]
```

### Additional Arguments

- `--app <app-id>`  
  Optional. Filters results to policies that include the app in their application condition.

- `--results <applied|exclusions|all>`  
  Optional. Policy Output Mode
  Default: applied

- `--db <path>`  
  Optional. Path to the `roadrecon.db` file used for resolution.  
  Default: `roadrecon.db`

---

## what-if

### What it does

`what-if` evaluates Conditional Access policies for a **hypothetical sign-in scenario** for a specific user.  
Instead of just showing which policies targer the user, this command asks:

> **If this user signs in under these conditions, what policies would actually apply?**

This is useful for quickly testing enforcement outcomes across different sign-in contexts (platform, client app type, risk signals, trusted location, etc.) without needing access to live sign-in logs or running tests in the tenant.

Because some Conditional Access conditions depend on signals you may not provide (or that aren’t fully modeled yet), CAPSlock separates results into:
- **Applied (definitive)** — policies that clearly apply given the scenario inputs
- **Applied (signal-dependent)** — policies that *might* apply depending on missing or unmodeled signals (for example, named locations or risk signals not supplied)

### Syntax

```bash
python3 CAPSlock.py what-if -u <userprincipalname> --resource <resource-id> [options]
python3 CAPSlock.py what-if -u <userprincipalname> --acr <user-action> [options]
```

### Additional Arguments

- `--resource <resource-id>`  
  Required if `--acr` is not supplied. Resource / cloud app / resource set (Default = `All`).

- `--acr <acr>`  
  Required if `--resource` is not supplied. User action / ACR (for example: `urn:user:registerdevice`).

- `--db <path>`  
  Optional. Path to the `roadrecon.db` file used for resolution.  
  Default: `roadrecon.db`  

- `--trusted-location <true|false>`  
  Optional. Trusted location flag.

- `--platform <windows|macos|linux|ios|android>`  
  Optional. Device platform (Default = `windows`).

- `--client-app <browser|mobileAppsAndDesktopClients|exchangeActiveSync|exchangeActiveSync|other>`  
  Optional. Client app type.

- `--signin-risk <none|low|medium|high>`  
  Optional. Sign-in risk level.

- `--user-risk <low|medium|high>`  
  Optional. User risk level.

- `--auth-flow <devicecodeflow|authtransfer>`  
  Optional. Authentication flow.

- `--device-filter <true|false>`  
  Optional. Device filter match flag.

- `--strict`  
  Optional. Only show policies that definitively apply (hide signal-dependent policies).

---

## analyze

### What it does

`analyze` systematically searches for Conditional Access enforcement gaps by permuting sign-in scenarios for a given user and resource (or user action).

Instead of evaluating a single hypothetical sign-in like `what-if`, this command asks:

> **Across all realistic sign-in conditions, where does Conditional Access fail to definitively enforce?**

You provide a user and either a **resource** or **ACR**. Any additional sign-in attributes you specify (platform, trusted location, risk level, etc.) are held constant. Anything you don’t specify is automatically permuted up to a configurable limit.

For each generated scenario, CAPSlock evaluates policies offline and records scenarios where gaps are detected, such as:
- No definitive policies applying
- Enforcement relying solely on report-only policies
- Trusted-location scenarios that bypass enforcement

### Syntax

```bash
python3 CAPSlock.py analyze -u <userprincipalname> --resource <resource-id> [options]
python3 CAPSlock.py analyze -u <userprincipalname> --acr <acr> [options]
```

### Additional Arguments

- `--resource <resource-id>`  
  Required if `--acr` is not supplied. Resource / cloud app / resource set to evaluate.

- `--acr <acr>`  
  Required if `--resoruce` not supplied. User action / Authentication Context Class Reference (for example: `urn:user:registerdevice`).

- `--db <path>`  
  Optional. Path to the `roadrecon.db` file used for resolution.  
  Default: `roadrecon.db`

- `--trusted-location <true|false>`  
  Optional. Indicates whether the sign-in originates from a trusted location.  
  If provided, the value is fixed; otherwise it is permuted.

- `--platform <windows|macos|linux|ios|android>`  
  Optional. Device platform.  
  If not specified, all platforms are permuted.

- `--client-app <browser|mobileAppsAndDesktopClients|exchangeActiveSync|other>`  
  Optional. Client application type.  
  If not specified, all client types are permuted.

- `--signin-risk <none|low|medium|high>`  
  Optional. Sign-in risk level.  
  If not specified, all risk levels are permuted.

- `--user-risk <low|medium|high>`  
  Optional. User risk level.  
  If not specified, all risk levels are permuted.

- `--auth-flow <devicecodeflow|authtransfer>`  
  Optional. Authentication flow.  
  If not specified, all supported flows are permuted.

- `--device-filter <true|false>`  
  Optional. Indicates whether the device filter condition matches.  
  If not specified, both values are permuted.

- `--entra-joined <true|false>`  
  Optional. Device join state flag.

- `--device-compliant <true|false>`  
  Optional. Device compliance flag.

- `--max-scenarios <n>`  
  Optional. Maximum number of scenarios to evaluate.  
  Default: `1000`.

- `--out <prefix>`  
  Optional. Output file prefix for generated analysis files.  
  Default: `capslock_analyze`.

---

## convert

### What it does

`convert` translates between **object IDs (GUIDs)** and **human-readable names** using the offline `roadrecon.db`.

It supports users, groups, directory roles, applications, and service principals.


### Syntax

```bash
python3 CAPSlock.py convert (--id <object-id> | --name <friendly-name>) [options]
```

### Additional Arguments

- `--db <path>`
  Optional. Path to the `roadrecon.db` file used for resolution.
  Default: `roadrecon.db`

---

## web-gui

### What it does

`web-gui` starts an interactive web interface for CAPSlock, providing a browser-based alternative to the command-line interface.

This is useful for:
- Exploring Conditional Access policies interactively
- Sharing results with team members who prefer a GUI
- Running quick what-if scenarios without constructing CLI commands

### Syntax

```bash
python3 CAPSlock.py web-gui [options]
```

### Additional Arguments

- `--host <host>`
  Optional. Host address to bind the web server to.
  Default: `0.0.0.0` (accessible from all network interfaces)

- `--port <port>`
  Optional. Port number for the web server.
  Default: `8000`

- `--reload`
  Optional. Enable auto-reload for development (server restarts when code changes are detected).

### Example Usage

```bash
python3 CAPSlock.py web-gui

python3 CAPSlock.py web-gui --port 8080

python3 CAPSlock.py web-gui --host 127.0.0.1 --reload
```

Once started, open your browser to `http://localhost:8000` (or the configured host/port) to access the interface.
