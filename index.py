import json
from time import sleep
import xml.etree.ElementTree as ET
import utils.snykApi as snykApi
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import typer
from enum import Enum

class CycloneDXVersion(str, Enum):
    v1_4 = "1.4"
    v1_5 = "1.5"
    v1_6 = "1.6"
    
class CycloneDXGenerator:
    def __init__(self, bazel_deps_xml: str):
        """Initialize with Bazel dependencies XML file content."""
        self.tree = ET.fromstring(bazel_deps_xml)
        self.components = self._extract_components()
        self.dependencies = self._extract_dependencies()

    def _extract_components(self) -> List[Dict]:
        """Extract components from Bazel dependencies."""
        components = []
        for rule in self.tree.findall(".//rule[@class='jvm_import']"):
            tags = rule.find(".//list[@name='tags']")
            if tags is None:
                continue

            maven_coords = None
            for tag in tags.findall('string'):
                if tag.get('value', '').startswith('maven_coordinates='):
                    maven_coords = tag.get('value').split('=')[1]
                    break
            
            if maven_coords:
                group_artifact_version = maven_coords.split(':')
                if len(group_artifact_version) == 3:
                    group, artifact, version = group_artifact_version
                    components.append({
                        "type": "library",
                        "name": artifact,
                        "group": group,
                        "version": version,
                        "purl": f"pkg:maven/{group}/{artifact}@{version}"
                    })
        
        return components

    def _extract_dependencies(self) -> List[Dict]:
        """Extract dependency relationships."""
        dependencies = []
        for rule in self.tree.findall(".//rule[@class='jvm_import']"):
            deps = rule.find(".//list[@name='deps']")
            if deps is None:
                continue

            name = rule.get('name', '')
            if name.startswith('@maven//'):
                maven_coords = None
                tags = rule.find(".//list[@name='tags']")
                if tags is not None:
                    for tag in tags.findall('string'):
                        if tag.get('value', '').startswith('maven_coordinates='):
                            maven_coords = tag.get('value').split('=')[1]
                            break
                
                if maven_coords:
                    group, artifact, version = maven_coords.split(':')
                    dep_refs = []
                    for dep in deps.findall('label'):
                        dep_value = dep.get('value', '')
                        if dep_value.startswith('@maven//'):
                            # Find corresponding component for this dependency
                            for comp in self.components:
                                if dep_value.endswith(comp['name'].replace('-', '_')):
                                    dep_refs.append(comp['purl'])
                    
                    if dep_refs:
                        dependencies.append({
                            "ref": f"pkg:maven/{group}/{artifact}@{version}",
                            "dependsOn": dep_refs
                        })

        return dependencies

    def generate_1_4(self) -> Dict:
        """Generate CycloneDX 1.4 JSON format."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": [
                    {
                        "vendor": "Bazel",
                        "name": "java-maven"
                    }
                ]
            },
            "components": self.components,
            "dependencies": self.dependencies
        }

    def generate_1_5(self) -> Dict:
        """Generate CycloneDX 1.5 JSON format."""
        bom_1_5 = self.generate_1_4()
        bom_1_5["specVersion"] = "1.5"
        # Add 1.5 specific fields
        bom_1_5["metadata"]["lifecycles"] = [
            {
                "phase": "build"
            }
        ]
        for component in bom_1_5["components"]:
            component["evidence"] = {
                "identity": {
                    "field": "maven-coordinate",
                    "confidence": 1.0
                }
            }
        return bom_1_5

    def generate_1_6(self) -> Dict:
        """Generate CycloneDX 1.6 JSON format."""
        bom_1_6 = self.generate_1_5()
        bom_1_6["specVersion"] = "1.6"
        # Add 1.6 specific fields
        bom_1_6["metadata"]["properties"] = [
            {
                "name": "build-system",
                "value": "bazel"
            }
        ]
        for component in bom_1_6["components"]:
            component["properties"] = [
                {
                    "name": "maven-central",
                    "value": "true"
                }
            ]
        return bom_1_6

def generate_cyclonedx_sbom(bazel_deps_xml: str, version: CycloneDXVersion) -> str:
    generator = CycloneDXGenerator(bazel_deps_xml)
    
    version_map = {
        CycloneDXVersion.v1_4: generator.generate_1_4,
        CycloneDXVersion.v1_5: generator.generate_1_5,
        CycloneDXVersion.v1_6: generator.generate_1_6
    }
    
    return json.dumps(version_map[version](), indent=2)

app = typer.Typer()
@app.command()
def generate_sbom(
    input_file: Path = typer.Option(..., "--input", "-i", help="Input Bazel deps XML file"),
    output_file: Path = typer.Option(..., "--output", "-o", help="Output SBOM JSON file"),
    version: CycloneDXVersion = typer.Option(CycloneDXVersion.v1_4, "--version", "-v", help="CycloneDX version to generate")
):
    """
    Generate a CycloneDX SBOM from Bazel dependencies XML file.
    """
    try:
        # Read input XML file
        if not input_file.exists():
            raise typer.BadParameter(f"Input file {input_file} does not exist")
        
        with open(input_file, "r") as f:
            bazel_deps_xml = f.read()
        
        # Generate SBOM
        sbom = generate_cyclonedx_sbom(bazel_deps_xml, version)
        
        # Write output JSON file
        with open(output_file, "w") as f:
            f.write(sbom)
        
        typer.echo(f"Successfully generated CycloneDX {version} SBOM: {output_file}")
    
    except Exception as e:
        typer.echo(f"Error generating SBOM: {str(e)}", err=True)
        raise typer.Exit(1)
    
@app.command()
def test_sbom(
    input_file: Path = typer.Option(..., "--input", "-i", help="sbom.json file generated by generate_sbom command"),
    org_id: str = typer.Option(..., "--org-id", "-o", help="Snyk org ID"),
):
    """
    Test the SBOM generation.
    """
    print("Testing SBOM generation...")
    try:
        with open(input_file, "r") as f:
            sbom_data = json.load(f)
        
        sbom_test_run_response = snykApi.create_sbom_test_run(org_id, sbom_data)
        # Extract test run ID from the response
        if isinstance(sbom_test_run_response, dict) and 'data' in sbom_test_run_response:
            test_run_id = sbom_test_run_response['data'].get('id')
            print("Test run ID:", test_run_id)
            if test_run_id:
                status_response = snykApi.get_sbom_test_run_status(org_id, test_run_id)
                print("Test run status:", status_response)
            else:
                print("Error: Could not find test run ID in response")
                raise typer.Exit(1)
        else:
            print(f"Error in SBOM test run: {sbom_test_run_response}")
            raise typer.Exit(1)
            
    except Exception as e:
        print(f"Error during SBOM test: {str(e)}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app() 