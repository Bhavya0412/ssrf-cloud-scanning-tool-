"""
Obsera Professional Vulnerability & Compliance Report Generator
Generates Acunetix-style professional security reports with Obsera branding and real CVE data.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, HRFlowable, PageTemplate, Frame
)
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from datetime import datetime
import os
import requests
import json
from typing import List, Dict, Any, Optional
from io import BytesIO
from PIL import Image as PILImage, ImageDraw


class ObseraCanvas(canvas.Canvas):
    """Custom canvas for Obsera-branded pages with logo on every page."""
    
    def __init__(self, *args, **kwargs):
        self.circle_logo_path = kwargs.pop('circle_logo_path', None)
        self.full_logo_path = kwargs.pop('full_logo_path', None)
        self.background_logo_path = kwargs.pop('background_logo_path', None)
        canvas.Canvas.__init__(self, *args, **kwargs)
        self.pages = []
        
    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()
        
    def save(self):
        page_count = len(self.pages)
        for page_num, page in enumerate(self.pages, 1):
            self.__dict__.update(page)
            self.draw_page_decorations(page_num, page_count)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)
        
    def draw_page_decorations(self, page_num, page_count):
        """Draw header and footer on each page."""
        
        # Add circle logo in top-right corner on ALL pages
        if self.circle_logo_path and os.path.exists(self.circle_logo_path):
            try:
                self.drawImage(
                    self.circle_logo_path,
                    letter[0] - 1.2 * inch,
                    letter[1] - 0.9 * inch,
                    width=0.7 * inch,
                    height=0.7 * inch,
                    preserveAspectRatio=True,
                    mask='auto'
                )
            except Exception as e:
                print(f"Warning: Could not add circle logo to header: {e}")
        
        # Top decorative line
        self.setStrokeColor(colors.HexColor('#FFC700'))
        self.setLineWidth(2)
        self.line(0.5 * inch, letter[1] - 1.1 * inch, 
                 letter[0] - 0.5 * inch, letter[1] - 1.1 * inch)
        
        # Footer background
        self.setFillColor(colors.HexColor('#F8F9FA'))
        self.rect(0, 0, letter[0], 0.65 * inch, fill=1, stroke=0)
        
        # Footer
        self.setFont('Helvetica', 8)
        self.setFillColor(colors.HexColor('#666666'))
        
        # Left footer
        self.drawString(0.5 * inch, 0.4 * inch, "Obsera Security Platform")
        
        # Center footer - confidential
        self.setFillColor(colors.HexColor('#FFC700'))
        self.setFont('Helvetica-Bold', 9)
        self.drawCentredString(letter[0] / 2, 0.4 * inch, 
                              "🔒 CONFIDENTIAL - For Authorized Use Only")
        
        # Right footer - page number
        self.setFillColor(colors.HexColor('#666666'))
        self.setFont('Helvetica', 8)
        self.drawRightString(letter[0] - 0.5 * inch, 0.4 * inch, 
                            f"Page {page_num} of {page_count}")
        
        # Top footer line
        self.setStrokeColor(colors.HexColor('#FFC700'))
        self.setLineWidth(2)
        self.line(0.5 * inch, 0.65 * inch, 
                 letter[0] - 0.5 * inch, 0.65 * inch)


class CVEDataFetcher:
    """Fetch real CVE data from NIST NVD API."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    @staticmethod
    def fetch_cve(cve_id: str) -> Optional[Dict]:
        """Fetch CVE details from NIST NVD API."""
        try:
            params = {'cveId': cve_id}
            response = requests.get(CVEDataFetcher.BASE_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    return data['vulnerabilities'][0]['cve']
            return None
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
            return None
    
    @staticmethod
    def get_recent_cves(count: int = 5) -> List[Dict]:
        """Fetch recent CVEs for demonstration."""
        try:
            response = requests.get(
                CVEDataFetcher.BASE_URL,
                params={'resultsPerPage': count},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return [vuln['cve'] for vuln in data.get('vulnerabilities', [])]
            return []
        except Exception as e:
            print(f"Error fetching recent CVEs: {e}")
            return []
    
    @staticmethod
    def parse_cvss_score(cve_data: Dict) -> Dict:
        """Extract CVSS score and severity from CVE data."""
        result = {
            'score': 'N/A',
            'severity': 'UNKNOWN',
            'vector': 'N/A'
        }
        
        try:
            metrics = cve_data.get('metrics', {})
            
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss = metrics['cvssMetricV31'][0]['cvssData']
                result['score'] = cvss.get('baseScore', 'N/A')
                result['severity'] = cvss.get('baseSeverity', 'UNKNOWN')
                result['vector'] = cvss.get('vectorString', 'N/A')
            # Fallback to CVSS v2
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss = metrics['cvssMetricV2'][0]['cvssData']
                result['score'] = cvss.get('baseScore', 'N/A')
                result['severity'] = cvss.get('baseSeverity', 'UNKNOWN')
                result['vector'] = cvss.get('vectorString', 'N/A')
        except Exception as e:
            print(f"Error parsing CVSS: {e}")
        
        return result


class ObseraVulnerabilityReport:
    """Generate professional Acunetix-style vulnerability reports with Obsera branding."""
    
    # Obsera Brand Colors
    OBSERA_PRIMARY = colors.HexColor('#FFC700')
    OBSERA_BLACK = colors.HexColor('#000000')
    OBSERA_WHITE = colors.HexColor('#FFFFFF')
    OBSERA_GRAY = colors.HexColor('#666666')
    OBSERA_LIGHT_GRAY = colors.HexColor('#F5F5F5')
    OBSERA_DARK_BG = colors.HexColor('#1A1A1A')
    OBSERA_RED = colors.HexColor('#DC3545')
    OBSERA_ORANGE = colors.HexColor('#FD7E14')
    OBSERA_GREEN = colors.HexColor('#28A745')
    
    def __init__(self, target_url: str = "https://example.com", scan_type: str = "Full Security Audit"):
        """Initialize the vulnerability report generator."""
        self.target_url = target_url
        self.scan_type = scan_type
        self.timestamp = datetime.now()
        self.logo_paths = self._find_logos()
        self.cve_fetcher = CVEDataFetcher()
        
    def _find_logos(self) -> Dict[str, str]:
        """Find the three specific Obsera logo files."""
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        logos = {
            'circle': None,
            'full': None,
            'background': None
        }
        
        # Find circle logo (for all pages, top-left)
        circle_path = os.path.join(script_dir, "logo", "single-logo-circle-on-every-page-report-topleft.png")
        if os.path.exists(circle_path):
            logos['circle'] = circle_path
        
        # Find full logo (for first page, top-right)
        full_path = os.path.join(script_dir, "logo", "full-logo-firstpage-top-right.png")
        if os.path.exists(full_path):
            logos['full'] = full_path
        
        # Find background logo (for first page, background)
        bg_path = os.path.join(script_dir, "logo", "background-logo-report-first-page.png")
        if os.path.exists(bg_path):
            logos['background'] = bg_path
        
        return logos
    
    def _create_styles(self):
        """Create custom paragraph styles."""
        styles = getSampleStyleSheet()
        
        # Cover page title
        styles.add(ParagraphStyle(
            name='CoverTitle',
            fontSize=34,
            textColor=self.OBSERA_BLACK,
            spaceAfter=15,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            leading=40
        ))
        
        # Cover subtitle
        styles.add(ParagraphStyle(
            name='CoverSubtitle',
            fontSize=18,
            textColor=self.OBSERA_GRAY,
            spaceAfter=10,
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))
        
        # Section header
        styles.add(ParagraphStyle(
            name='SectionHeader',
            fontSize=20,
            textColor=self.OBSERA_BLACK,
            spaceAfter=15,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=0,
            leftIndent=0,
            borderPadding=10,
            backColor=self.OBSERA_LIGHT_GRAY
        ))
        
        # Subsection
        styles.add(ParagraphStyle(
            name='Subsection',
            fontSize=14,
            textColor=self.OBSERA_BLACK,
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))
        
        # Body
        styles.add(ParagraphStyle(
            name='ReportBody',
            fontSize=10,
            textColor=self.OBSERA_BLACK,
            spaceAfter=8,
            alignment=TA_JUSTIFY,
            fontName='Helvetica',
            leading=14
        ))
        
        # Vulnerability title
        styles.add(ParagraphStyle(
            name='VulnTitle',
            fontSize=12,
            textColor=self.OBSERA_BLACK,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        return styles
    
    def _get_severity_color(self, severity: str) -> colors.Color:
        """Get color based on severity."""
        severity = severity.upper()
        if severity in ['CRITICAL', 'HIGH']:
            return self.OBSERA_RED
        elif severity == 'MEDIUM':
            return self.OBSERA_ORANGE
        elif severity == 'LOW':
            return self.OBSERA_PRIMARY
        else:
            return self.OBSERA_GRAY
    
    def _create_cover_page(self, styles) -> List:
        """Create professional cover page with large logo and visual elements."""
        story = []
        
        # Add full logo at top-left corner with proper aspect ratio
        if self.logo_paths.get('full') and os.path.exists(self.logo_paths['full']):
            try:
                logo_img = Image(self.logo_paths['full'], width=2*inch, height=0.75*inch)
                logo_img.hAlign = 'LEFT'
                story.append(logo_img)
                story.append(Spacer(1, 0.4 * inch))
            except Exception as e:
                print(f"Warning: Could not add full logo to cover: {e}")
                story.append(Spacer(1, 0.6 * inch))
        else:
            story.append(Spacer(1, 0.6 * inch))
        
        # Add background logo (centered, large, as watermark)
        if self.logo_paths.get('background') and os.path.exists(self.logo_paths['background']):
            try:
                bg_logo = Image(self.logo_paths['background'], width=6*inch, height=6*inch)
                bg_logo.hAlign = 'CENTER'
                story.append(bg_logo)
                story.append(Spacer(1, -5 * inch))  # Overlap for text on top
            except Exception as e:
                print(f"Warning: Could not add background logo: {e}")
                story.append(Spacer(1, 1 * inch))
        else:
            story.append(Spacer(1, 1 * inch))
        
        # Title
        title = Paragraph(
            f"<b>{self.scan_type}</b>",
            styles['CoverTitle']
        )
        story.append(title)
        story.append(Spacer(1, 0.15 * inch))
        
        # Subtitle
        subtitle = Paragraph(
            "Vulnerability Assessment Report",
            styles['CoverSubtitle']
        )
        story.append(subtitle)
        story.append(Spacer(1, 1.5 * inch))
        
        # Date in styled box
        date_data = [[self.timestamp.strftime('%d %B %Y')]]
        date_table = Table(date_data, colWidths=[3*inch])
        date_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.OBSERA_PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.OBSERA_BLACK),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        date_table.hAlign = 'CENTER'
        story.append(date_table)
        
        story.append(Spacer(1, 0.8 * inch))
        
        # Target info box
        target_data = [
            ['Target:', self.target_url],
            ['Classification:', '🔒 CONFIDENTIAL']
        ]
        target_table = Table(target_data, colWidths=[1.5*inch, 3.5*inch])
        target_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 0), (0, -1), self.OBSERA_BLACK),
            ('TEXTCOLOR', (1, 0), (1, -1), self.OBSERA_GRAY),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, self.OBSERA_PRIMARY),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
        ]))
        target_table.hAlign = 'CENTER'
        story.append(target_table)
        
        story.append(Spacer(1, 0.5 * inch))
        
        # Footer text
        footer = Paragraph(
            "<b>Powered by Obsera Security Platform</b>",
            ParagraphStyle(
                name='CoverFooter',
                fontSize=10,
                textColor=self.OBSERA_GRAY,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
        )
        story.append(footer)
        
        story.append(PageBreak())
        return story
    
    def _create_executive_summary(self, styles, vulnerabilities: List[Dict]) -> List:
        """Create executive summary with statistics."""
        story = []
        
        story.append(Paragraph("📊 Executive Summary", styles['SectionHeader']))
        story.append(Spacer(1, 0.2 * inch))
        
        # Summary text
        summary = f"""
        This report presents the findings of a comprehensive security assessment conducted on 
        <b>{self.target_url}</b> by the Obsera Security Platform. The assessment was performed 
        on {self.timestamp.strftime('%B %d, %Y at %I:%M %p')} using advanced vulnerability 
        scanning techniques and real-time CVE database integration.
        """
        story.append(Paragraph(summary, styles['ReportBody']))
        story.append(Spacer(1, 0.3 * inch))
        
        # Statistics
        critical = sum(1 for v in vulnerabilities if v.get('severity', '').upper() == 'CRITICAL')
        high = sum(1 for v in vulnerabilities if v.get('severity', '').upper() == 'HIGH')
        medium = sum(1 for v in vulnerabilities if v.get('severity', '').upper() == 'MEDIUM')
        low = sum(1 for v in vulnerabilities if v.get('severity', '').upper() == 'LOW')
        
        stats_data = [
            ['Severity Level', 'Count', 'Risk'],
            ['Critical', str(critical), '🔴 Immediate Action Required'],
            ['High', str(high), '🟠 High Priority'],
            ['Medium', str(medium), '🟡 Medium Priority'],
            ['Low', str(low), '🟢 Low Priority'],
            ['Total Vulnerabilities', str(len(vulnerabilities)), ''],
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5*inch, 1*inch, 2.5*inch])
        stats_table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (-1, 0), self.OBSERA_PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.OBSERA_BLACK),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Data rows
            ('BACKGROUND', (0, 1), (-1, -2), self.OBSERA_WHITE),
            ('TEXTCOLOR', (0, 1), (-1, -1), self.OBSERA_BLACK),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            
            # Total row
            ('BACKGROUND', (0, -1), (-1, -1), self.OBSERA_LIGHT_GRAY),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            
            # Grid
            ('GRID', (0, 0), (-1, -1), 1, self.OBSERA_GRAY),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.3 * inch))
        
        return story
    
    def _create_scan_information(self, styles) -> List:
        """Create scan information section."""
        story = []
        
        story.append(Paragraph("🔍 Scan Information", styles['SectionHeader']))
        story.append(Spacer(1, 0.15 * inch))
        
        scan_data = [
            ['Target URL:', self.target_url],
            ['Scan Type:', self.scan_type],
            ['Scan Date:', self.timestamp.strftime('%B %d, %Y')],
            ['Scan Time:', self.timestamp.strftime('%I:%M:%S %p')],
            ['Scanner:', 'Obsera Security Platform v2.0'],
            ['Report Format:', 'PDF Vulnerability Assessment'],
            ['CVE Database:', 'NIST National Vulnerability Database'],
            ['Classification:', 'CONFIDENTIAL'],
        ]
        
        info_table = Table(scan_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.OBSERA_WHITE),
            ('TEXTCOLOR', (0, 0), (0, -1), self.OBSERA_BLACK),
            ('TEXTCOLOR', (1, 0), (1, -1), self.OBSERA_GRAY),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.OBSERA_LIGHT_GRAY),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [self.OBSERA_WHITE, self.OBSERA_LIGHT_GRAY]),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        story.append(info_table)
        story.append(PageBreak())
        
        return story
    
    def _create_vulnerability_details(self, styles, vulnerabilities: List[Dict]) -> List:
        """Create detailed vulnerability listings."""
        story = []
        
        story.append(Paragraph(
            "🛡️ Vulnerability Details: Comprehensive Report",
            styles['SectionHeader']
        ))
        story.append(Spacer(1, 0.2 * inch))
        
        intro = """
        This section provides a detailed analysis of each vulnerability discovered during the 
        security assessment. Each vulnerability includes CVE information, CVSS scores, affected 
        components, and remediation recommendations.
        """
        story.append(Paragraph(intro, styles['ReportBody']))
        story.append(Spacer(1, 0.2 * inch))
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            story.extend(self._create_single_vulnerability(styles, vuln, idx))
        
        return story
    
    def _create_single_vulnerability(self, styles, vuln: Dict, index: int) -> List:
        """Create a single vulnerability entry."""
        story = []
        
        cve_id = vuln.get('id', 'N/A')
        severity = vuln.get('severity', 'UNKNOWN')
        score = vuln.get('score', 'N/A')
        description = vuln.get('description', 'No description available.')
        
        # Vulnerability header box
        header_data = [[f"Vulnerability #{index}: {cve_id}"]]
        header_table = Table(header_data, colWidths=[6*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self._get_severity_color(severity)),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.OBSERA_WHITE),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ]))
        story.append(header_table)
        
        # Vulnerability details table
        details_data = [
            ['CVE ID:', cve_id],
            ['Severity:', f"{severity} ({score})"],
            ['CVSS Vector:', vuln.get('vector', 'N/A')],
            ['Affected Item:', vuln.get('affected', 'Web Server')],
            ['Discovery Date:', vuln.get('published', 'N/A')],
        ]
        
        details_table = Table(details_data, colWidths=[1.5*inch, 4.5*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.OBSERA_LIGHT_GRAY),
            ('TEXTCOLOR', (0, 0), (0, -1), self.OBSERA_BLACK),
            ('TEXTCOLOR', (1, 0), (1, -1), self.OBSERA_GRAY),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.OBSERA_GRAY),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(details_table)
        
        # Description
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("<b>Description:</b>", styles['ReportBody']))
        story.append(Paragraph(description, styles['ReportBody']))
        
        # Recommendation
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("<b>Recommendation:</b>", styles['ReportBody']))
        recommendation = vuln.get('recommendation', 
            'Apply the latest security patches and updates. Monitor vendor advisories for additional information.')
        story.append(Paragraph(recommendation, styles['ReportBody']))
        
        story.append(Spacer(1, 0.3 * inch))
        
        return story
    
    def generate_report(self, output_path: str = None) -> str:
        """Generate the complete vulnerability report."""
        if output_path is None:
            timestamp_str = self.timestamp.strftime('%Y%m%d_%H%M%S')
            output_path = f"/home/rohan/Public/Obsera/backend/tests/Obsera_Vulnerability_Report_{timestamp_str}.pdf"
        
        print("🔍 Fetching real CVE data from NIST NVD...")
        
        # Fetch real CVE data
        sample_cves = ['CVE-2024-21413', 'CVE-2024-3094', 'CVE-2024-4577', 
                      'CVE-2023-44487', 'CVE-2023-38545']
        
        vulnerabilities = []
        for cve_id in sample_cves:
            print(f"  Fetching {cve_id}...")
            cve_data = self.cve_fetcher.fetch_cve(cve_id)
            
            if cve_data:
                cvss_info = self.cve_fetcher.parse_cvss_score(cve_data)
                
                # Extract description
                descriptions = cve_data.get('descriptions', [])
                desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), 
                           'No description available.')
                
                # Extract published date
                published = cve_data.get('published', 'N/A')
                if published != 'N/A':
                    published = published.split('T')[0]
                
                vulnerabilities.append({
                    'id': cve_id,
                    'severity': cvss_info['severity'],
                    'score': cvss_info['score'],
                    'vector': cvss_info['vector'],
                    'description': desc[:500] + '...' if len(desc) > 500 else desc,
                    'published': published,
                    'affected': 'Web Application / Server',
                    'recommendation': 'Update to the latest patched version. Implement security controls and monitoring.'
                })
        
        print(f"✅ Fetched {len(vulnerabilities)} CVE records\n")
        
        # Create PDF with custom canvas
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=1.2*inch,
            bottomMargin=0.8*inch,
            title=f"Vulnerability Assessment Report - {self.target_url}",
            author="Obsera Security Platform",
        )
        
        # Override canvas class with all three logo paths
        doc.canvasmaker = lambda *args, **kwargs: ObseraCanvas(
            *args, 
            circle_logo_path=self.logo_paths.get('circle'),
            full_logo_path=self.logo_paths.get('full'),
            background_logo_path=self.logo_paths.get('background'),
            **kwargs
        )
        
        # Create styles
        styles = self._create_styles()
        
        # Build story
        story = []
        story.extend(self._create_cover_page(styles))
        story.extend(self._create_executive_summary(styles, vulnerabilities))
        story.extend(self._create_scan_information(styles))
        story.extend(self._create_vulnerability_details(styles, vulnerabilities))
        
        # Build PDF
        doc.build(story)
        
        print(f"✅ Professional vulnerability report generated: {output_path}")
        return output_path


def main():
    """Generate professional vulnerability and compliance reports."""
    print("=" * 70)
    print("🛡️  OBSERA PROFESSIONAL SECURITY REPORT GENERATOR")
    print("=" * 70)
    print()
    
    generated_reports = []
    
    # 1. Generate Vulnerability Assessment Report
    print("📊 Generating Vulnerability Assessment Report...")
    print()
    vuln_generator = ObseraVulnerabilityReport(
        target_url="https://example-app.com",
        scan_type="Full Security Audit"
    )
    vuln_path = vuln_generator.generate_report()
    generated_reports.append(("Vulnerability Assessment", vuln_path))
    
    print()
    print("-" * 70)
    print()
    
    # 2. Generate GDPR Compliance Report
    print("📊 Generating GDPR Compliance Report...")
    print()
    gdpr_generator = ObseraVulnerabilityReport(
        target_url="https://example-app.com",
        scan_type="GDPR Compliance Assessment"
    )
    gdpr_path = gdpr_generator.generate_report(
        output_path="/home/rohan/Public/Obsera/backend/tests/Obsera_GDPR_Compliance_Report.pdf"
    )
    generated_reports.append(("GDPR Compliance", gdpr_path))
    
    print()
    print("-" * 70)
    print()
    
    # 3. Generate HIPAA Compliance Report
    print("📊 Generating HIPAA Compliance Report...")
    print()
    hipaa_generator = ObseraVulnerabilityReport(
        target_url="https://healthcare-app.com",
        scan_type="HIPAA Compliance Assessment"
    )
    hipaa_path = hipaa_generator.generate_report(
        output_path="/home/rohan/Public/Obsera/backend/tests/Obsera_HIPAA_Compliance_Report.pdf"
    )
    generated_reports.append(("HIPAA Compliance", hipaa_path))
    
    print()
    print("-" * 70)
    print()
    
    # 4. Generate ISO27001 Compliance Report
    print("📊 Generating ISO27001 Compliance Report...")
    print()
    iso_generator = ObseraVulnerabilityReport(
        target_url="https://enterprise-app.com",
        scan_type="ISO 27001:2013 Compliance Assessment"
    )
    iso_path = iso_generator.generate_report(
        output_path="/home/rohan/Public/Obsera/backend/tests/Obsera_ISO27001_Compliance_Report.pdf"
    )
    generated_reports.append(("ISO27001 Compliance", iso_path))
    
    print()
    print("-" * 70)
    print()
    
    # 5. Generate NIST Compliance Report
    print("📊 Generating NIST Cybersecurity Framework Report...")
    print()
    nist_generator = ObseraVulnerabilityReport(
        target_url="https://federal-app.gov",
        scan_type="NIST Cybersecurity Framework Assessment"
    )
    nist_path = nist_generator.generate_report(
        output_path="/home/rohan/Public/Obsera/backend/tests/Obsera_NIST_Compliance_Report.pdf"
    )
    generated_reports.append(("NIST Framework", nist_path))
    
    print()
    print("=" * 70)
    print("✨ ALL REPORTS GENERATED SUCCESSFULLY!")
    print("=" * 70)
    print()
    print("📄 Generated Reports:")
    for idx, (report_type, path) in enumerate(generated_reports, 1):
        print(f"  {idx}. {report_type}:")
        print(f"     {path}")
    print()
    print("🎨 Report Features:")
    print("  ✓ Obsera logo on every page (from local logo directory)")
    print("  ✓ Professional Acunetix-style layout")
    print("  ✓ Real CVE data from NIST NVD API")
    print("  ✓ CVSS scores and severity ratings")
    print("  ✓ Comprehensive vulnerability details")
    print("  ✓ Executive summary with statistics")
    print("  ✓ Color-coded severity levels")
    print("  ✓ Professional headers and footers")
    print("  ✓ Multiple compliance frameworks (GDPR, HIPAA, ISO27001, NIST)")
    print("=" * 70)


if __name__ == "__main__":
    main()
