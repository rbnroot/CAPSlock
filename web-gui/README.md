# CAPSlock Web GUI

A modern web interface for CAPSlock - the offline Conditional Access policy analysis tool.

## Features

- **Get Policies**: List all CA policies that apply to a specific user
- **What-If Analysis**: Test hypothetical sign-in scenarios
- **Analyze Gaps**: Systematically search for CA enforcement gaps

## Setup

### 1. Install Dependencies

First, make sure you have the base CAPSlock dependencies installed:

```bash
pip install -r requirements.txt
```

Then install the web-specific dependencies:

```bash
pip install -r requirements-web.txt
```

### 2. Ensure Database is Available

Make sure you have a `roadrecon.db` file in the project root. If you don't have one, use [ROADtools](https://github.com/dirkjanm/ROADtools) to gather data:

```bash
# Authenticate
roadrecon auth

# Gather data
roadrecon gather

# This creates roadrecon.db
```

## Running the Web Interface

### Start the Server

From the project root directory:

```bash
python3 web_api.py
```

Or use uvicorn directly for more control:

```bash
uvicorn web_api:app --host 0.0.0.0 --port 8000 --reload
```

### Access the Web Interface

Open your browser and navigate to:

```
http://localhost:8000
```
