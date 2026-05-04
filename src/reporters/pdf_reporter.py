"""
PDF Report Generator
Creates professional PDF security reports with charts and formatting.
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from datetime import datetime
from pathlib import Path
from typing import List
import io


class PDFReporter:
    """
    Generate professional PDF security reports.
    
    Features:
    - Executive summary
    - Risk distribution charts
    - Detailed findings tables
    - MITRE ATT&CK coverage
    - Configuration issues
    - Remediation guidance
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Create custom paragraph styles"""
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#667eea'),
            spaceBefore=20,
            spaceAfter=12,
            borderWidth=1,
            borderColor=colors.HexColor('#667eea'),
            borderPadding=5
        ))
        
        # Subsection style
        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#764ba2'),
            spaceBefore=10,
            spaceAfter=8
        ))
    
    def generate_report(self, network_results: List, service_results: List,
                       mitre_findings: List, config_issues: List,
                       output_file: str):
        """
        Generate complete PDF report.
        
        Args:
            network_results: Network scan results
            service_results: Service enumeration results
            mitre_findings: MITRE mappings
            config_issues: Configuration issues
            output_file: Output PDF path
        """
        print(f"[*] Generating PDF report...")
        
        # Create PDF document
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        story = []
        
        # Build report content
        story.extend(self._build_cover_page())
        story.append(PageBreak())
        
        story.extend(self._build_executive_summary(
            network_results, service_results, mitre_findings, config_issues
        ))
        story.append(Spacer(1, 0.3*inch))
        
        story.extend(self._build_risk_section(mitre_findings, config_issues))
        story.append(Spacer(1, 0.3*inch))
        
        story.extend(self._build_findings_section(mitre_findings))
        story.append(PageBreak())
        
        story.extend(self._build_config_issues_section(config_issues))
        story.append(Spacer(1, 0.3*inch))
        
        story.extend(self._build_mitre_section(mitre_findings))
        story.append(PageBreak())
        
        story.extend(self._build_recommendations_section(config_issues, mitre_findings))
        
        # Build PDF
        doc.build(story)
        
        print(f"[+] PDF report saved to {output_file}")
    
    def _build_cover_page(self) -> List:
        """Build cover page"""
        elements = []
        
        # Title
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph(
            "🛡️ Attack Surface Mapper",
            self.styles['CustomTitle']
        ))
        
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph(
            "Security Assessment Report",
            self.styles['Heading2']
        ))
        
        elements.append(Spacer(1, 1*inch))
        
        # Report info
        report_info = f"""
        <para alignment="center">
        <b>Generated:</b> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}<br/>
        <b>Report Type:</b> Attack Surface Analysis<br/>
        <b>Prepared By:</b> Attack Surface Mapper v1.0<br/>
        </para>
        """
        elements.append(Paragraph(report_info, self.styles['Normal']))
        
        elements.append(Spacer(1, 2*inch))
        
        # Footer
        footer_text = """
        <para alignment="center" fontSize="10" textColor="gray">
        <i>CONFIDENTIAL - For Authorized Personnel Only</i><br/>
        This report contains sensitive security information
        </para>
        """
        elements.append(Paragraph(footer_text, self.styles['Normal']))
        
        return elements
    
    def _build_executive_summary(self, network_results, service_results, 
                                mitre_findings, config_issues) -> List:
        """Build executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Statistics
        total_hosts = len(set(r.ip for r in network_results))
        total_ports = len(network_results)
        total_vulns = sum(len(s.vulnerabilities) for s in service_results 
                         if hasattr(s, 'vulnerabilities') and s.vulnerabilities)
        
        critical_issues = len([c for c in config_issues if c.severity == 'CRITICAL'])
        high_issues = len([c for c in config_issues if c.severity == 'HIGH'])
        
        unique_techniques = len(set(t.technique_id for f in mitre_findings for t in f.techniques))
        
        summary_text = f"""
        This security assessment identified the following key findings:<br/><br/>
        
        <b>Scan Coverage:</b><br/>
        • Hosts Scanned: {total_hosts}<br/>
        • Open Ports Discovered: {total_ports}<br/>
        • Services Enumerated: {len(service_results)}<br/><br/>
        
        <b>Security Findings:</b><br/>
        • Critical Configuration Issues: {critical_issues}<br/>
        • High Severity Issues: {high_issues}<br/>
        • Known Vulnerabilities (CVEs): {total_vulns}<br/>
        • MITRE ATT&CK Techniques Identified: {unique_techniques}<br/><br/>
        
        <b>Risk Assessment:</b><br/>
        The attack surface analysis reveals {'<font color="red">CRITICAL</font>' if critical_issues > 0 else '<font color="orange">ELEVATED</font>' if high_issues > 0 else '<font color="green">MODERATE</font>'} 
        risk exposure requiring immediate attention.
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        
        return elements
    
    def _build_risk_section(self, mitre_findings, config_issues) -> List:
        """Build risk distribution section"""
        elements = []
        
        elements.append(Paragraph("Risk Distribution", self.styles['SectionHeader']))
        
        # Risk counts
        risk_critical = len([f for f in mitre_findings if f.risk_score >= 7.0])
        risk_high = len([f for f in mitre_findings if 5.0 <= f.risk_score < 7.0])
        risk_medium = len([f for f in mitre_findings if 3.0 <= f.risk_score < 5.0])
        risk_low = len([f for f in mitre_findings if f.risk_score < 3.0])
        
        # Create table
        data = [
            ['Risk Level', 'Count', 'Percentage'],
            ['Critical (≥7.0)', str(risk_critical), f"{(risk_critical/len(mitre_findings)*100) if mitre_findings else 0:.1f}%"],
            ['High (5.0-6.9)', str(risk_high), f"{(risk_high/len(mitre_findings)*100) if mitre_findings else 0:.1f}%"],
            ['Medium (3.0-4.9)', str(risk_medium), f"{(risk_medium/len(mitre_findings)*100) if mitre_findings else 0:.1f}%"],
            ['Low (<3.0)', str(risk_low), f"{(risk_low/len(mitre_findings)*100) if mitre_findings else 0:.1f}%"]
        ]
        
        table = Table(data, colWidths=[2*inch, 1*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#ffebee')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#fff3e0')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fff9c4')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#e8f5e9')),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        elements.append(table)
        
        return elements
    
    def _build_findings_section(self, mitre_findings) -> List:
        """Build detailed findings table"""
        elements = []
        
        elements.append(Paragraph("Top Security Findings", self.styles['SectionHeader']))
        
        # Sort by risk score
        top_findings = sorted(mitre_findings, key=lambda x: x.risk_score, reverse=True)[:10]
        
        # Create table data
        data = [['IP:Port', 'Service', 'Risk', 'Score', 'Techniques']]
        
        for finding in top_findings:
            techniques_str = ', '.join([t.technique_id for t in finding.techniques[:2]])
            if len(finding.techniques) > 2:
                techniques_str += f" +{len(finding.techniques)-2}"
            
            risk_level = 'Critical' if finding.risk_score >= 7.0 else \
                        'High' if finding.risk_score >= 5.0 else \
                        'Medium' if finding.risk_score >= 3.0 else 'Low'
            
            service_str = finding.service
            if finding.version:
                service_str += f" {finding.version}"
            
            data.append([
                f"{finding.ip}:{finding.port}",
                service_str[:20],
                risk_level,
                f"{finding.risk_score}/10",
                techniques_str[:30]
            ])
        
        table = Table(data, colWidths=[1.3*inch, 1.5*inch, 0.8*inch, 0.7*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')])
        ]))
        
        elements.append(table)
        
        return elements
    
    def _build_config_issues_section(self, config_issues) -> List:
        """Build configuration issues section"""
        elements = []
        
        elements.append(Paragraph("Configuration Issues", self.styles['SectionHeader']))
        
        if not config_issues:
            elements.append(Paragraph("✅ No configuration issues detected.", self.styles['Normal']))
            return elements
        
        # Group by severity
        critical = [c for c in config_issues if c.severity == 'CRITICAL']
        high = [c for c in config_issues if c.severity == 'HIGH']
        
        # Show critical issues
        if critical:
            elements.append(Paragraph("Critical Issues", self.styles['SubSection']))
            for issue in critical[:5]:
                issue_text = f"""
                <b>{issue.title}</b><br/>
                <i>Location:</i> {issue.ip}:{issue.port}<br/>
                <i>Issue:</i> {issue.description}<br/>
                <font color="green"><i>Remediation:</i> {issue.remediation}</font>
                """
                elements.append(Paragraph(issue_text, self.styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
        
        # Show high issues
        if high:
            elements.append(Paragraph("High Severity Issues", self.styles['SubSection']))
            for issue in high[:5]:
                issue_text = f"""
                <b>{issue.title}</b><br/>
                <i>Location:</i> {issue.ip}:{issue.port}<br/>
                <i>Issue:</i> {issue.description}<br/>
                <font color="green"><i>Remediation:</i> {issue.remediation}</font>
                """
                elements.append(Paragraph(issue_text, self.styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_mitre_section(self, mitre_findings) -> List:
        """Build MITRE ATT&CK section"""
        elements = []
        
        elements.append(Paragraph("MITRE ATT&CK Analysis", self.styles['SectionHeader']))
        
        # Collect all techniques and tactics
        all_techniques = {}
        all_tactics = set()
        
        for finding in mitre_findings:
            for tech in finding.techniques:
                if tech.technique_id not in all_techniques:
                    all_techniques[tech.technique_id] = tech
                all_tactics.update(tech.tactics)
        
        summary_text = f"""
        The attack surface analysis identified <b>{len(all_techniques)}</b> potential attack techniques 
        spanning <b>{len(all_tactics)}</b> MITRE ATT&CK tactics.<br/><br/>
        
        <b>Covered Tactics:</b><br/>
        {', '.join([t.replace('-', ' ').title() for t in sorted(all_tactics)])}
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Top techniques table
        elements.append(Paragraph("Identified Techniques", self.styles['SubSection']))
        
        data = [['Technique ID', 'Name', 'Tactics']]
        for tech_id, tech in list(all_techniques.items())[:10]:
            tactics_str = ', '.join([t.replace('-', ' ').title() for t in tech.tactics[:2]])
            data.append([tech_id, tech.name[:40], tactics_str[:40]])
        
        table = Table(data, colWidths=[1.2*inch, 3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')])
        ]))
        
        elements.append(table)
        
        return elements
    
    def _build_recommendations_section(self, config_issues, mitre_findings) -> List:
        """Build recommendations section"""
        elements = []
        
        elements.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        
        recommendations = [
            "Address all CRITICAL configuration issues immediately",
            "Patch identified vulnerabilities based on CVSS severity",
            "Implement network segmentation to limit lateral movement",
            "Enable logging and monitoring for detected attack techniques",
            "Conduct regular attack surface assessments",
            "Implement principle of least privilege across all services",
            "Disable unnecessary services and close unused ports"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        footer_text = """
        <para alignment="center" fontSize="10" textColor="gray">
        <i>--- End of Report ---</i><br/>
        Generated by Attack Surface Mapper | Built by Ahmed Dahdouh
        </para>
        """
        elements.append(Paragraph(footer_text, self.styles['Normal']))
        
        return elements


def main():
    """Test PDF reporter"""
    print("PDF Reporter - Use through main.py pipeline")


if __name__ == '__main__':
    main()
