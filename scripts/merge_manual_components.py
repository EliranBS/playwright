import json
import sys
import argparse
from datetime import datetime, timezone

def merge_sboms(base_path, manual_path, output_path):
    try:
        # Load the base auto-generated SBOM
        with open(base_path, 'r', encoding='utf-8') as f:
            base_sbom = json.load(f)
            
        # Load the manual components SBOM
        with open(manual_path, 'r', encoding='utf-8') as f:
            manual_sbom = json.load(f)
            
        # Ensure manual SBOM has 'components' array
        if 'components' not in manual_sbom or not isinstance(manual_sbom['components'], list):
            print("Error: 'manual-components.json' must contain a 'components' array.")
            sys.exit(1)
            
        # Ensure base SBOM has 'components' array (create if missing)
        if 'components' not in base_sbom or not isinstance(base_sbom['components'], list):
            base_sbom['components'] = []
            
        base_components = base_sbom['components']
        manual_components = manual_sbom['components']
        
        # Track existing components to avoid duplicates
        existing_refs = {comp.get('bom-ref') for comp in base_components if comp.get('bom-ref')}
        existing_signatures = {
            f"{comp.get('type')}:{comp.get('name')}:{comp.get('version')}" 
            for comp in base_components
        }

        added_count = 0
        skipped_count = 0

        for manual_comp in manual_components:
            ref = manual_comp.get('bom-ref')
            sig = f"{manual_comp.get('type')}:{manual_comp.get('name')}:{manual_comp.get('version')}"
            
            # Deduplication logic
            if (ref and ref in existing_refs) or (sig in existing_signatures):
                print(f"Skipping {manual_comp.get('name')} (Duplicate bom-ref or signature found).")
                skipped_count += 1
                continue
                
            # Inject manual=true property
            if 'properties' not in manual_comp:
                manual_comp['properties'] = []
            
            has_manual_prop = any(p.get('name') == 'manual' for p in manual_comp['properties'])
            if not has_manual_prop:
                manual_comp['properties'].append({
                    "name": "manual",
                    "value": "true"
                })
                
            base_components.append(manual_comp)
            
            # Update trackers
            if ref:
                existing_refs.add(ref)
            existing_signatures.add(sig)
            
            added_count += 1
            print(f"Added manual component: {manual_comp.get('name')} (v{manual_comp.get('version', 'unknown')})")

        # Update metadata timestamp if metadata exists
        if 'metadata' in base_sbom and isinstance(base_sbom['metadata'], dict):
            base_sbom['metadata']['timestamp'] = datetime.now(timezone.utc).astimezone().isoformat()

        # Save the final merged SBOM
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(base_sbom, f, indent=2)
            
        # Print Summary
        print("\n--- Merge Summary ---")
        print(f"Original components : {len(base_components) - added_count}")
        print(f"Manual components read: {len(manual_components)}")
        print(f"Successfully added  : {added_count}")
        print(f"Skipped duplicates  : {skipped_count}")
        print(f"Total in final SBOM : {len(base_components)}")
        print(f"Output saved to     : {output_path}")
        print("---------------------\n")
        
        sys.exit(0)

    except FileNotFoundError as e:
        print(f"Error: File not found. {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format. Please ensure no comments exist in the JSON. {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error occurred during merge: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge manual CycloneDX components into auto-generated SBOM")
    parser.add_argument("--base", required=True, help="Path to base auto-generated JSON SBOM")
    parser.add_argument("--manual", required=True, help="Path to manual components JSON file")
    parser.add_argument("--output", required=True, help="Path to save the final merged JSON SBOM")
    args = parser.parse_args()
    
    merge_sboms(args.base, args.manual, args.output)