import scraper, threat_detector, threat_analyzer, text_processor, validators
from fpdf import FPDF
from datetime import datetime
from typing import Dict, Any

class CyberPulseEngine:
    @staticmethod
    def process_scan(url: str, selectors: Dict[str, bool]) -> Dict[str, Any]:
        valid, msg = validators.validate_url(url)
        if not valid: return {'status': 'failed', 'error': msg}

        raw = scraper.fetch_content(url)
        if raw['status'] == 'failed': return raw

        findings = threat_detector.extract_all_threats(raw['text'])
        findings['threat_analysis'] = threat_analyzer.analyze_threats(findings)

        return {
            'status': 'success', 'url': url, 'title': raw['title'],
            'threat_indicators': findings,
            'parsed_data': {k: raw[k.lower()] if selectors.get(k) else ([] if k != 'Text' else "") 
                            for k in ['Text', 'Links', 'Images', 'Metadata']},
            'clean_text': text_processor.sanitize_for_wordcloud(raw['text']),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    @staticmethod
    def export_to_pdf(data: Dict, path: str) -> bool:
        try:
            pdf = FPDF(); pdf.add_page()
            # Header
            pdf.set_fill_color(26, 26, 46); pdf.rect(0, 0, 210, 40, 'F')
            pdf.set_text_color(255, 255, 255); pdf.set_font("Courier", 'B', 24)
            pdf.cell(0, 15, "CYBER-PULSE PRO", 1, 1, 'C')
            # Summary Box
            ans = data['threat_indicators']['threat_analysis']
            pdf.set_text_color(0); pdf.set_font("Arial", 'B', 12); pdf.ln(25)
            pdf.cell(0, 10, f"Target: {data['url']} | {data['timestamp']}", 1, 1)
            pdf.set_fill_color(240); pdf.rect(10, 65, 190, 25, 'F')
            pdf.set_xy(15, 68); pdf.cell(0, 10, f"LEVEL: {ans['threat_level']} (Score: {ans['total_score']})")
            # Findings
            pdf.set_xy(10, 95); pdf.set_font("Arial", 'B', 14); pdf.cell(0, 10, "Indicators", 0, 1)
            inds = data['threat_indicators']
            for lbl, key in {"IPs": "ips", "CVEs": "cves", "BTC": "btc_addresses", "Malware": "malware_keywords"}.items():
                if inds.get(key):
                    pdf.set_font("Arial", 'B', 10); pdf.cell(0, 8, f"> {lbl}:", 0, 1)
                    pdf.set_font("Courier", '', 9)
                    for item in inds[key][:15]: pdf.cell(0, 5, f" - {item}", 0, 1)
            pdf.output(path); return True
        except: return False

# UI Mappings
process_scan = CyberPulseEngine.process_scan
export_results = lambda d, f, p: CyberPulseEngine.export_to_pdf(d, p)
validate_url = validators.validate_url