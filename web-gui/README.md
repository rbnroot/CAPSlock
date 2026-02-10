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

### API Documentation

FastAPI automatically generates API documentation. Access it at:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Using the Web Interface

### Get Policies

1. Navigate to the "Get Policies" tab
2. Enter the user's UPN (e.g., `user@domain.com`)
3. Optionally filter by application ID
4. Choose results mode (applied, exclusions, or all)
5. Click "Get Policies"

### What-If Analysis

1. Navigate to the "What-If" tab
2. Enter the user's UPN
3. Specify the sign-in scenario:
   - Resource/App ID OR ACR (choose one)
   - Platform (Windows, macOS, Linux, iOS, Android)
   - Client app type
   - Trusted location
   - Risk levels
   - Auth flow
4. Click "Run What-If"

Results are categorized as:
- **Definitive**: Policies that definitely apply
- **Signal-Dependent**: Policies that might apply based on runtime signals

### Analyze Gaps

1. Navigate to the "Analyze" tab
2. Enter the user's UPN
3. Specify either resource ID or ACR
4. Optionally fix specific parameters (others will be permuted)
5. Set max scenarios (default: 1000)
6. Click "Start Analysis"

The tool will permute scenarios and identify gaps such as:
- No policies applying
- Report-only bypasses
- Trusted location bypasses

## API Endpoints

### GET /api/policies

Get policies for a user.

**Parameters:**
- `user` (required): User Principal Name
- `app` (optional): Application ID filter
- `results` (optional): Results mode (applied, exclusions, all)
- `db_path` (optional): Path to roadrecon.db

**Example:**
```bash
curl "http://localhost:8000/api/policies?user=user@domain.com&results=applied"
```

### POST /api/what-if

Run what-if analysis.

**Body:**
```json
{
  "user": "user@domain.com",
  "resource": "00000000-0000-0000-0000-000000000000",
  "platform": "windows",
  "client_app": "browser",
  "trusted_location": true,
  "signin_risk": "low"
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/api/what-if \
  -H "Content-Type: application/json" \
  -d '{"user":"user@domain.com","resource":"All","platform":"windows"}'
```

### POST /api/analyze

Analyze CA gaps.

**Body:**
```json
{
  "user": "user@domain.com",
  "resource": "00000000-0000-0000-0000-000000000000",
  "max_scenarios": 1000,
  "platform": "windows"
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"user":"user@domain.com","resource":"All","max_scenarios":500}'
```

## Architecture

The web interface consists of:

### Backend (`web_api.py`)
- **FastAPI** framework for REST API
- **Pydantic** models for request/response validation
- Direct integration with existing CAPSlock business logic

### Serializers (`CAPSlock/serializers.py`)
- Converts `PolicyResult` objects to JSON
- Categorizes results for different views
- No changes to core CAPSlock code

### Frontend (`static/index.html`)
- Vanilla JavaScript (no framework dependencies)
- Responsive design
- Three main interfaces (Get Policies, What-If, Analyze)

## Development

### Running in Development Mode

```bash
uvicorn web_api:app --reload --log-level debug
```

### Customizing the Database Path

You can specify a custom database path in requests:

```python
# In API calls
{
  "user": "user@domain.com",
  "db_path": "/path/to/custom/roadrecon.db"
}
```

Or set it as default in `web_api.py`:

```python
from CAPSlock.db import DB_PATH
DB_PATH = "/custom/path/roadrecon.db"
```

### CORS Configuration

The API allows all origins by default. To restrict, modify `web_api.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Restrict origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## Deployment

### Production Deployment

For production, use a proper ASGI server:

```bash
# Using Gunicorn with Uvicorn workers
pip install gunicorn
gunicorn web_api:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements-web.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-web.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "web_api:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:

```bash
docker build -t capslock-web .
docker run -p 8000:8000 -v $(pwd)/roadrecon.db:/app/roadrecon.db capslock-web
```

## Troubleshooting

### "Module not found" errors

Make sure you're in the project root directory and have installed all dependencies:

```bash
pip install -r requirements.txt -r requirements-web.txt
```

### "roadrecon.db not found"

Ensure the database file exists in the project root or specify the path explicitly.

### Port already in use

Change the port:

```bash
python3 web_api.py --port 8001
# or
uvicorn web_api:app --port 8001
```

### CORS errors

If accessing from a different origin, ensure CORS is properly configured in `web_api.py`.

## Original CLI Still Available

The original command-line interface is still fully functional:

```bash
# Get policies
python3 CAPSlock.py get-policies -u user@domain.com

# What-if
python3 CAPSlock.py what-if -u user@domain.com --resource All --platform windows

# Analyze
python3 CAPSlock.py analyze -u user@domain.com --resource All --max-scenarios 1000
```

## Contributing

When adding new features:

1. Add backend logic to `web_api.py`
2. Add serialization if needed in `CAPSlock/serializers.py`
3. Update the frontend in `static/index.html`
4. Update this README

## License

Same as CAPSlock main project.
