# Contributing

This is a learning project, but contributions, suggestions, and bug reports
are welcome.

## Setup

```bash
git clone https://github.com/<your-username>/security-header-scanner.git
cd security-header-scanner
pip install -r requirements-dev.txt
```

## Running tests

```bash
pytest tests/ -v
```

## Adding a new header check

Open `scanner.py` and add an entry to the `SECURITY_HEADERS` dictionary near
the top of the file:

```python
SECURITY_HEADERS = {
    "Your-Header-Name": "One-line explanation of what it protects against",
    ...
}
```

## Adding a new sensitive path check

Add the path to the `SENSITIVE_PATHS` list, also near the top of the file:

```python
SENSITIVE_PATHS = [
    "/your/new/path",
    ...
]
```

## Before submitting a change

1. Run `pytest tests/` and make sure everything passes
2. Test the tool manually against a real site you control
3. Keep functions small and testable - network calls and logic are kept
   separate on purpose (see `evaluate_headers` vs `check_sensitive_paths`)