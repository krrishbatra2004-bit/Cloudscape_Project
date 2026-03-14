import os
import re

def refactor_imports(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.py', '.yaml', '.yml', '.json', '.md')):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Rule 1: engines -> discovery.engines
                content = re.sub(r'from engines(?:\.|\s)', r'from discovery.engines\g<0>', content)
                content = re.sub(r'import engines(?:\.|\s)', r'import discovery.engines\g<0>', content)
                
                # Rule 2: drivers -> discovery.drivers
                content = re.sub(r'from drivers(?:\.|\s)', r'from discovery.drivers\g<0>', content)
                content = re.sub(r'import drivers(?:\.|\s)', r'import discovery.drivers\g<0>', content)

                # Rule 3: core.logic -> intelligence
                content = re.sub(r'from core\.logic(?:\.|\s)', r'from intelligence\g<0>', content)
                content = re.sub(r'import core\.logic(?:\.|\s)', r'import intelligence\g<0>', content)

                # Rule 4: core.intelligence -> intelligence
                content = re.sub(r'from core\.intelligence(?:\.|\s)', r'from intelligence\g<0>', content)
                content = re.sub(r'import core\.intelligence(?:\.|\s)', r'import intelligence\g<0>', content)
                
                # Rule 5: core.simulation -> simulation
                content = re.sub(r'from core\.simulation(?:\.|\s)', r'from simulation\g<0>', content)
                content = re.sub(r'import core\.simulation(?:\.|\s)', r'import simulation\g<0>', content)
                
                # Rule 7: registry -> config
                content = re.sub(r'"registry/aws_services.json"', r'"config/service_registry.json"', content)
                content = re.sub(r"'registry/aws_services.json'", r"'config/service_registry.json'", content)

                # Cloudscape -> CloudScape
                content = content.replace('Cloudscape', 'CloudScape')

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)

if __name__ == "__main__":
    refactor_imports("d:/Cloudscape_Project/backend/src")
    refactor_imports("d:/Cloudscape_Project/backend/main.py")
    refactor_imports("d:/Cloudscape_Project/backend/scripts")
    refactor_imports("d:/Cloudscape_Project/backend/config")
    print("Codebase refactored.")
