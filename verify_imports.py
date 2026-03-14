import sys
import os
import importlib.util
from pathlib import Path

# Add backend and backend/src to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(PROJECT_ROOT / "backend/src"))

def verify_imports(directory):
    failed = []
    passed = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py') and file != '__init__.py':
                filepath = os.path.join(root, file)
                module_name = "test_mod_" + file.replace('.py', '')
                try:
                    spec = importlib.util.spec_from_file_location(module_name, filepath)
                    mod = importlib.util.module_from_spec(spec)
                    # We don't execute it if it does things on import, just compiling is okay, 
                    # but executing is better to catch import errors.
                    spec.loader.exec_module(mod)
                    passed += 1
                except Exception as e:
                    # Ignore known execution issues when running scripts directly
                    if "Cannot run" not in str(e):
                        failed.append((filepath, str(e)))
                        
    return passed, failed

if __name__ == "__main__":
    print("Testing backend/src...")
    p1, f1 = verify_imports("d:/Cloudscape_Project/backend/src")
    print("Testing backend/scripts...")
    p2, f2 = verify_imports("d:/Cloudscape_Project/backend/scripts")
    
    print(f"\nPassed: {p1 + p2}")
    if f1 or f2:
        print(f"Failed: {len(f1) + len(f2)}")
        for path, err in (f1 + f2):
            print(f"  {path} -> {err}")
        sys.exit(1)
    else:
        print("All imports resolved successfully.")
