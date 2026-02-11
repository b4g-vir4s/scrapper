"""
EXPORTERS MODULE
================
Pure functions for exporting data in various formats.
Handles JSON, CSV, Excel, and report generation.
"""

import json
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
    """
    PURE FUNCTION: Flattens nested dictionary
    
    Example:
        {'a': {'b': 1}} → {'a_b': 1}
    
    Args:
        d: Dictionary to flatten
        parent_key: Prefix for keys
        sep: Separator between nested keys
    
    Returns:
        Flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, ', '.join(map(str, v))))
        else:
            items.append((new_key, v))
    return dict(items)


def format_as_json(data: Dict) -> str:
    """
    PURE FUNCTION: Formats data as JSON string
    
    Args:
        data: Dictionary to format
    
    Returns:
        JSON string with indentation
    """
    timestamp = datetime.now().isoformat()
    export_data = {
        'timestamp': timestamp,
        'scan_results': data
    }
    return json.dumps(export_data, indent=2)


def format_as_csv_dict(data: Dict) -> Dict:
    """
    PURE FUNCTION: Formats data for CSV export
    
    Args:
        data: Dictionary to format
    
    Returns:
        Flattened dictionary suitable for CSV
    """
    timestamp = datetime.now().isoformat()
    export_data = {
        'timestamp': timestamp,
        'scan_results': data
    }
    return flatten_dict(export_data)


def create_summary_dict(data: Dict) -> Dict:
    """
    PURE FUNCTION: Creates summary data for export
    
    Args:
        data: Full scan data
    
    Returns:
        Summary dictionary with key metrics
    """
    threat_analysis = data.get('threat_indicators', {}).get('threat_analysis', {})
    
    return {
        'URL': data.get('url', 'N/A'),
        'Timestamp': data.get('timestamp', 'N/A'),
        'Threat_Level': threat_analysis.get('threat_level', 'N/A'),
        'Threat_Score': threat_analysis.get('total_score', 0),
        'Total_Indicators': threat_analysis.get('indicator_count', 0)
    }


def generate_text_report(data: Dict) -> str:
    """
    PURE FUNCTION: Generates detailed text report
    
    Args:
        data: Full scan data
    
    Returns:
        Formatted text report
    """
    indicators = data.get('threat_indicators', {})
    threat_analysis = indicators.get('threat_analysis', {})
    
    report = f"""
{'=' * 80}
CYBER-PULSE PRO - THREAT INTELLIGENCE REPORT
{'=' * 80}

SCAN INFORMATION:
{'-' * 80}
URL: {data.get('url', 'N/A')}
Scan Time: {data.get('timestamp', 'N/A')}

THREAT ASSESSMENT:
{'-' * 80}
Threat Level: {threat_analysis.get('threat_level', 'N/A')}
Threat Score: {threat_analysis.get('total_score', 0)}
Description: {threat_analysis.get('description', 'N/A')}
Total Indicators: {threat_analysis.get('indicator_count', 0)}

"""
    
    # Add indicator details
    indicator_sections = [
        ('IP Addresses', 'ips'),
        ('CVE Identifiers', 'cves'),
        ('Email Addresses', 'emails'),
        ('Bitcoin Addresses', 'btc_addresses'),
        ('MD5 Hashes', 'md5_hashes'),
        ('SHA1 Hashes', 'sha1_hashes'),
        ('SHA256 Hashes', 'sha256_hashes'),
        ('Malware Keywords', 'malware_keywords')
    ]
    
    for section_name, key in indicator_sections:
        items = indicators.get(key, [])
        if items:
            report += f"\n{section_name.upper()} ({len(items)}):\n{'-' * 80}\n"
            for item in items[:10]:  # Show first 10
                report += f"  • {item}\n"
            if len(items) > 10:
                report += f"  ... and {len(items) - 10} more\n"
    
    report += f"\n{'=' * 80}\n"
    report += "End of Report\n"
    report += f"{'=' * 80}\n"
    
    return report


def save_as_json(data: Dict, filepath: str) -> bool:
    """
    Saves data as JSON file
    
    Args:
        data: Dictionary to save
        filepath: Path to save file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, 'w') as f:
            f.write(format_as_json(data))
        return True
    except Exception as e:
        print(f"Error saving JSON: {e}")
        return False


def save_as_csv(data: Dict, filepath: str) -> bool:
    """
    Saves data as CSV file
    
    Args:
        data: Dictionary to save
        filepath: Path to save file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        flat_data = format_as_csv_dict(data)
        df = pd.DataFrame([flat_data])
        df.to_csv(filepath, index=False)
        return True
    except Exception as e:
        print(f"Error saving CSV: {e}")
        return False


def save_as_excel(data: Dict, filepath: str) -> bool:
    """
    Saves data as Excel file with multiple sheets
    
    Args:
        data: Dictionary to save
        filepath: Path to save file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            # Summary sheet
            summary = create_summary_dict(data)
            pd.DataFrame([summary]).to_excel(writer, sheet_name='Summary', index=False)
            
            # Threat Indicators sheet
            indicators = data.get('threat_indicators', {})
            if 'threat_analysis' in indicators:
                # Remove threat_analysis from indicators for this sheet
                indicators_copy = {k: v for k, v in indicators.items() if k != 'threat_analysis'}
                flat_indicators = flatten_dict(indicators_copy)
                pd.DataFrame([flat_indicators]).to_excel(writer, sheet_name='Threat Indicators', index=False)
            
            # Parsed Data sheet
            parsed = data.get('parsed_data', {})
            if parsed:
                flat_parsed = flatten_dict(parsed)
                pd.DataFrame([flat_parsed]).to_excel(writer, sheet_name='Extracted Data', index=False)
        
        return True
    except Exception as e:
        print(f"Error saving Excel: {e}")
        return False


def save_as_text_report(data: Dict, filepath: str) -> bool:
    """
    Saves data as text report
    
    Args:
        data: Dictionary to save
        filepath: Path to save file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, 'w') as f:
            f.write(generate_text_report(data))
        return True
    except Exception as e:
        print(f"Error saving text report: {e}")
        return False