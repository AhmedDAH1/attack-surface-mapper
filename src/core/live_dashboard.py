"""
Live Terminal Dashboard
Real-time ASCII dashboard showing scan progress with charts and animations.
"""

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text
from rich.align import Align
from datetime import datetime
import time


class LiveDashboard:
    """
    Interactive terminal dashboard for real-time scan visualization.
    
    Features:
    - Live progress tracking
    - Real-time statistics
    - Threat level indicators
    - ASCII art banners
    - Color-coded severity
    """
    
    def __init__(self):
        self.console = Console()
        self.stats = {
            'ports_scanned': 0,
            'ports_open': 0,
            'services_found': 0,
            'vulnerabilities': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'compliance_score': 100
        }
        self.findings = []
        self.start_time = None
    
    def create_banner(self) -> Panel:
        """Create ASCII art banner"""
        banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗   ║
    ║    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝   ║
    ║    ███████║   ██║      ██║   ███████║██║     █████╔╝    ║
    ║    ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗    ║
    ║    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗   ║
    ║    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ║
    ║                                                           ║
    ║         SURFACE MAPPER  -  Real-Time Assessment          ║
    ╚═══════════════════════════════════════════════════════════╝
        """
        return Panel(
            Align.center(Text(banner, style="bold cyan")),
            border_style="cyan"
        )
    
    def create_stats_panel(self) -> Table:
        """Create live statistics table"""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold white")
        table.add_column("Status", justify="right")
        
        # Ports
        port_status = "🟢" if self.stats['ports_open'] == 0 else "🟡"
        table.add_row(
            "Ports Scanned",
            str(self.stats['ports_scanned']),
            port_status
        )
        
        table.add_row(
            "Open Ports",
            str(self.stats['ports_open']),
            "🔴" if self.stats['ports_open'] > 10 else "🟡" if self.stats['ports_open'] > 0 else "🟢"
        )
        
        # Services
        table.add_row(
            "Services Identified",
            str(self.stats['services_found']),
            ""
        )
        
        # Vulnerabilities
        vuln_status = "🔴" if self.stats['vulnerabilities'] > 0 else "🟢"
        table.add_row(
            "Known Vulnerabilities",
            str(self.stats['vulnerabilities']),
            vuln_status
        )
        
        # Issues
        table.add_row(
            "Critical Issues",
            f"[red]{self.stats['critical_issues']}[/red]" if self.stats['critical_issues'] > 0 else "0",
            "🔴" if self.stats['critical_issues'] > 0 else "🟢"
        )
        
        table.add_row(
            "High Severity Issues",
            f"[yellow]{self.stats['high_issues']}[/yellow]" if self.stats['high_issues'] > 0 else "0",
            "🟡" if self.stats['high_issues'] > 0 else "🟢"
        )
        
        # Compliance
        score = self.stats['compliance_score']
        score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        table.add_row(
            "Compliance Score",
            f"[{score_color}]{score}/100[/{score_color}]",
            "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
        )
        
        return Panel(table, title="[bold cyan]Live Statistics[/bold cyan]", border_style="cyan")
    
    def create_threat_meter(self) -> Panel:
        """Create threat level meter"""
        critical = self.stats['critical_issues']
        high = self.stats['high_issues']
        vulns = self.stats['vulnerabilities']
        
        threat_score = (critical * 30) + (high * 15) + (vulns * 5)
        
        if threat_score == 0:
            level = "LOW"
            color = "green"
            emoji = "✅"
        elif threat_score < 50:
            level = "MODERATE"
            color = "yellow"
            emoji = "⚠️"
        elif threat_score < 100:
            level = "HIGH"
            color = "orange"
            emoji = "🔶"
        else:
            level = "CRITICAL"
            color = "red"
            emoji = "🔴"
        
        # ASCII threat meter
        meter = f"""
        Threat Level: [{color}]{level}[/{color}] {emoji}
        
        ████████████████████████████████████████████████
        {'█' * min(50, threat_score // 2)}
        
        Score: {threat_score}/200
        """
        
        return Panel(
            Align.center(Text(meter)),
            title="[bold]Threat Assessment[/bold]",
            border_style=color
        )
    
    def create_recent_findings(self) -> Panel:
        """Create recent findings panel"""
        table = Table(show_header=True, box=None)
        table.add_column("Time", style="dim")
        table.add_column("Finding", style="white")
        table.add_column("Severity", justify="right")
        
        # Show last 5 findings
        for finding in self.findings[-5:]:
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'yellow',
                'MEDIUM': 'orange',
                'LOW': 'green'
            }.get(finding['severity'], 'white')
            
            table.add_row(
                finding['time'],
                finding['description'],
                f"[{severity_color}]{finding['severity']}[/{severity_color}]"
            )
        
        if not self.findings:
            table.add_row("--:--:--", "No findings yet...", "")
        
        return Panel(
            table,
            title="[bold cyan]Recent Findings[/bold cyan]",
            border_style="cyan"
        )
    
    def create_layout(self) -> Layout:
        """Create dashboard layout"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=13),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3)
        )
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        layout["left"].split_column(
            Layout(name="stats"),
            Layout(name="threat")
        )
        
        # Set content
        layout["header"].update(self.create_banner())
        layout["stats"].update(self.create_stats_panel())
        layout["threat"].update(self.create_threat_meter())
        layout["right"].update(self.create_recent_findings())
        
        # Footer
        elapsed = time.time() - self.start_time if self.start_time else 0
        footer_text = f"⏱️  Elapsed: {int(elapsed)}s  |  📍 Scanning in progress...  |  Press Ctrl+C to stop"
        layout["footer"].update(Panel(Align.center(footer_text), border_style="dim"))
        
        return layout
    
    def update_stats(self, **kwargs):
        """Update statistics"""
        self.stats.update(kwargs)
    
    def add_finding(self, description: str, severity: str):
        """Add a new finding"""
        self.findings.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'description': description,
            'severity': severity
        })
    
    def start_scan(self, target: str):
        """Display scan start message"""
        self.start_time = time.time()
        self.console.print(f"\n[bold cyan]🎯 Target:[/bold cyan] {target}")
        self.console.print("[bold green]⚡ Starting attack surface assessment...[/bold green]\n")
    
    def render(self):
        """Render the dashboard"""
        return self.create_layout()


def demo():
    """Demo the dashboard"""
    dashboard = LiveDashboard()
    dashboard.start_scan("192.168.1.100")
    
    with Live(dashboard.render(), refresh_per_second=4, console=dashboard.console) as live:
        # Simulate scanning
        for i in range(100):
            dashboard.update_stats(
                ports_scanned=i,
                ports_open=min(i // 10, 5),
                services_found=min(i // 20, 3),
                vulnerabilities=min(i // 25, 2),
                critical_issues=1 if i > 50 else 0,
                high_issues=min(i // 30, 3),
                compliance_score=max(50, 100 - i // 2)
            )
            
            if i == 20:
                dashboard.add_finding("Port 22 (SSH) - OpenSSH 7.4", "HIGH")
            if i == 40:
                dashboard.add_finding("Default credentials detected", "CRITICAL")
            if i == 60:
                dashboard.add_finding("Unencrypted HTTP traffic", "HIGH")
            if i == 80:
                dashboard.add_finding("Version disclosure in banner", "LOW")
            
            live.update(dashboard.render())
            time.sleep(0.1)
    
    dashboard.console.print("\n[bold green]✅ Scan complete![/bold green]\n")


if __name__ == '__main__':
    demo()
