import os, sys
def run_audit():
    print('--- CLOUDSCAPE INTEGRITY AUDIT ---')
    print(f'Python Path: {sys.executable}')
    print(f'Azure Config: {os.environ.get("AZURE_CONFIG_DIR")}')
    print(f'NLP Cache: {os.environ.get("HF_HOME")}')
    print('----------------------------------')
    if 'C:' in sys.executable:
        print('[ALERT] Venv is on C: Drive!')
    else:
        print('[SUCCESS] System is isolated on D/E Drives.')

run_audit()
