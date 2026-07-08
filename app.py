import sys
from pathlib import Path

# Add backend to sys.path so backend imports work
backend_path = Path(__file__).parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.append(str(backend_path))

# Run the actual app from the frontend directory
frontend_app_path = Path(__file__).parent / "frontend" / "app.py"
exec_globals = dict(globals())
exec_globals["__file__"] = str(frontend_app_path)

exec(frontend_app_path.read_text(encoding="utf-8"), exec_globals)
