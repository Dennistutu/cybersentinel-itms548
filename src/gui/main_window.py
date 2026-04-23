"""
CyberSentinel Main GUI Window
Tkinter-based graphical user interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import logging
from datetime import datetime

from database.db_manager import DatabaseManager
from utils.config import config
from api.nvd_api import NVDAPI
from api.abuseipdb_api import AbuseIPDBAPI
from api.virustotal_api import VirusTotalAPI
from api.otx_api import AlienVaultOTXAPI
from analysis.data_analyzer import DataAnalyzer

logger = logging.getLogger("cybersentinel")

class CyberSentinelApp:
    """Main application GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("CyberSentinel - Threat Intelligence Dashboard")
        self.root.geometry("1200x800")
        
        # Initialize database
        self.db = DatabaseManager()
        
        # Initialize API clients
        self.nvd_api = NVDAPI()
        self.abuseipdb_api = AbuseIPDBAPI()
        self.virustotal_api = VirusTotalAPI()
        self.otx_api = AlienVaultOTXAPI()
        
        # Initialize data analyzer
        self.analyzer = DataAnalyzer(self.db)
        
        # Setup GUI
        self.setup_styles()
        self.create_menu()
        self.create_main_layout()
        
        # Load initial data
        self.refresh_dashboard()
        
        logger.info("GUI initialized successfully")
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#2E75B6')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10))
        
    def create_menu(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Settings", command=self.show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Refresh Dashboard", command=self.refresh_dashboard)
        tools_menu.add_command(label="Clear Cache", command=self.clear_cache)
        tools_menu.add_command(label="Export Data", command=self.export_data)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="API Setup Guide", command=self.show_api_guide)
    
    def create_main_layout(self):
        """Create main application layout"""
        
        # Header
        header_frame = tk.Frame(self.root, bg='#2E75B6', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title = tk.Label(
            header_frame, 
            text="🛡️ CyberSentinel",
            font=('Arial', 24, 'bold'),
            bg='#2E75B6',
            fg='white'
        )
        title.pack(side='left', padx=20, pady=10)
        
        subtitle = tk.Label(
            header_frame,
            text="Threat Intelligence Dashboard",
            font=('Arial', 12),
            bg='#2E75B6',
            fg='white'
        )
        subtitle.pack(side='left', padx=5, pady=10)
        
        # Status bar in header
        self.status_label = tk.Label(
            header_frame,
            text="Status: Ready",
            font=('Arial', 10),
            bg='#2E75B6',
            fg='white'
        )
        self.status_label.pack(side='right', padx=20, pady=10)
        
        # Main content area with notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_vulnerability_tab()
        self.create_ip_reputation_tab()
        self.create_scan_tab()
        self.create_threat_intel_tab()
        self.create_analytics_tab()  # NEW: Data visualization tab
        
        # Footer
        footer_frame = tk.Frame(self.root, bg='#F0F0F0', height=30)
        footer_frame.pack(fill='x', side='bottom')
        footer_frame.pack_propagate(False)
        
        footer_text = tk.Label(
            footer_frame,
            text="ITMS 548 - Illinois Institute of Technology | Team: Dennis, Yemi, Will",
            font=('Arial', 9),
            bg='#F0F0F0'
        )
        footer_text.pack(pady=5)
    
    def create_dashboard_tab(self):
        """Create dashboard overview tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Dashboard")
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(tab, text="System Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        # Create stats grid
        self.stats_labels = {}
        stats = [
            ("total_vulnerabilities", "Total Vulnerabilities:"),
            ("total_ip_checks", "IP Reputation Checks:"),
            ("total_scans", "File/URL Scans:"),
            ("total_threat_pulses", "Threat Intelligence Pulses:")
        ]
        
        for i, (key, label_text) in enumerate(stats):
            row = i // 2
            col = i % 2 * 2
            
            label = ttk.Label(stats_frame, text=label_text, font=('Arial', 10, 'bold'))
            label.grid(row=row, column=col, sticky='w', padx=10, pady=5)
            
            value_label = ttk.Label(stats_frame, text="0", font=('Arial', 10))
            value_label.grid(row=row, column=col+1, sticky='w', padx=10, pady=5)
            
            self.stats_labels[key] = value_label
        
        # Recent Activity Frame
        activity_frame = ttk.LabelFrame(tab, text="Recent Activity Log", padding=10)
        activity_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Activity log text widget
        self.activity_log = scrolledtext.ScrolledText(
            activity_frame,
            height=15,
            font=('Courier', 9),
            state='disabled'
        )
        self.activity_log.pack(fill='both', expand=True)
        
        # Add initial message
        self.log_activity("CyberSentinel initialized successfully")
        self.log_activity("Waiting for user actions...")
        
        # Refresh button
        refresh_btn = ttk.Button(
            tab,
            text="🔄 Refresh Dashboard",
            command=self.refresh_dashboard
        )
        refresh_btn.pack(pady=10)
    
    def create_vulnerability_tab(self):
        """Create vulnerability search tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 Vulnerabilities")
        
        # Search Frame
        search_frame = ttk.LabelFrame(tab, text="Search CVE Database (NVD)", padding=10)
        search_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(search_frame, text="Search Term:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.cve_search_entry = ttk.Entry(search_frame, width=40)
        self.cve_search_entry.grid(row=0, column=1, padx=5, pady=5)
        
        search_btn = ttk.Button(
            search_frame,
            text="Search",
            command=self.search_vulnerabilities
        )
        search_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(tab, text="Search Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Results text widget
        self.cve_results = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            font=('Courier', 9)
        )
        self.cve_results.pack(fill='both', expand=True)
        
        # Add demo message
        self.cve_results.insert('end', "Enter search term and click Search to query NVD API\n\n")
        self.cve_results.insert('end', "Example searches:\n")
        self.cve_results.insert('end', "- CVE-2024-1234\n")
        self.cve_results.insert('end', "- Microsoft\n")
        self.cve_results.insert('end', "- Apache\n")
        self.cve_results.config(state='disabled')
    
    def create_ip_reputation_tab(self):
        """Create IP reputation check tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 IP Reputation")
        
        # Input Frame
        input_frame = ttk.LabelFrame(tab, text="Check IP Address (AbuseIPDB)", padding=10)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(input_frame, text="IP Address:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.ip_entry = ttk.Entry(input_frame, width=30)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        check_btn = ttk.Button(
            input_frame,
            text="Check Reputation",
            command=self.check_ip_reputation
        )
        check_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(tab, text="Reputation Report", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.ip_results = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            font=('Courier', 9)
        )
        self.ip_results.pack(fill='both', expand=True)
        
        # Add demo message
        self.ip_results.insert('end', "Enter an IP address to check its reputation\n\n")
        self.ip_results.insert('end', "Example IPs to test:\n")
        self.ip_results.insert('end', "- 8.8.8.8 (Google DNS - should be clean)\n")
        self.ip_results.insert('end', "- 1.1.1.1 (Cloudflare DNS - should be clean)\n")
        self.ip_results.config(state='disabled')
    
    def create_scan_tab(self):
        """Create file/URL scan tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔎 Scan")
        
        # Input Frame
        input_frame = ttk.LabelFrame(tab, text="Scan URL or File Hash (VirusTotal)", padding=10)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(input_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.scan_entry = ttk.Entry(input_frame, width=50)
        self.scan_entry.grid(row=0, column=1, padx=5, pady=5)
        
        scan_btn = ttk.Button(
            input_frame,
            text="Scan",
            command=self.scan_target
        )
        scan_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(tab, text="Scan Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.scan_results = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            font=('Courier', 9)
        )
        self.scan_results.pack(fill='both', expand=True)
        
        # Add demo message
        self.scan_results.insert('end', "Enter URL or file hash to scan\n\n")
        self.scan_results.insert('end', "Examples:\n")
        self.scan_results.insert('end', "- https://www.example.com\n")
        self.scan_results.insert('end', "- File SHA-256 hash\n")
        self.scan_results.config(state='disabled')
    
    def create_threat_intel_tab(self):
        """Create threat intelligence tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚡ Threat Intel")
        
        # Search Frame
        search_frame = ttk.LabelFrame(tab, text="Search Threat Pulses (AlienVault OTX)", padding=10)
        search_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.threat_search_entry = ttk.Entry(search_frame, width=40)
        self.threat_search_entry.grid(row=0, column=1, padx=5, pady=5)
        
        search_btn = ttk.Button(
            search_frame,
            text="Search Pulses",
            command=self.search_threat_intel
        )
        search_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(tab, text="Threat Intelligence Feed", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.threat_results = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            font=('Courier', 9)
        )
        self.threat_results.pack(fill='both', expand=True)
        
        # Add demo message
        self.threat_results.insert('end', "Search for threat intelligence pulses\n\n")
        self.threat_results.insert('end', "Example searches:\n")
        self.threat_results.insert('end', "- ransomware\n")
        self.threat_results.insert('end', "- phishing\n")
        self.threat_results.insert('end', "- malware\n")
        self.threat_results.config(state='disabled')
    
    def create_analytics_tab(self):
        """Create data analytics and visualization tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📈 Analytics")
        
        # Control Frame
        control_frame = ttk.Frame(tab, padding=10)
        control_frame.pack(fill='x')
        
        ttk.Label(control_frame, text="Data Analysis & Visualization", font=('Arial', 12, 'bold')).pack(side='left', padx=10)
        
        refresh_btn = ttk.Button(
            control_frame,
            text="🔄 Refresh Charts",
            command=self.refresh_analytics
        )
        refresh_btn.pack(side='left', padx=5)
        
        export_btn = ttk.Button(
            control_frame,
            text="📊 Export Report",
            command=self.export_report
        )
        export_btn.pack(side='left', padx=5)
        
        # Create scrollable frame for charts
        canvas_frame = tk.Frame(tab)
        canvas_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        canvas = tk.Canvas(canvas_frame)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        self.analytics_frame = ttk.Frame(canvas)
        
        self.analytics_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.analytics_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Initial load
        self.refresh_analytics()
    
    def refresh_analytics(self):
        """Refresh all analytics charts"""
        try:
            self.update_status("Generating analytics...")
            
            # Clear existing charts
            for widget in self.analytics_frame.winfo_children():
                widget.destroy()
            
            # Row 1: Summary Stats
            stats_frame = ttk.LabelFrame(self.analytics_frame, text="Summary Statistics", padding=10)
            stats_frame.grid(row=0, column=0, columnspan=2, sticky='ew', padx=5, pady=5)
            
            stats = self.db.get_statistics()
            stats_text = f"""
            Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}
            Total IP Checks: {stats.get('total_ip_checks', 0)}
            Total Scans: {stats.get('total_scans', 0)}
            Total Threat Pulses: {stats.get('total_threat_pulses', 0)}
            """
            
            ttk.Label(stats_frame, text=stats_text, font=('Courier', 10)).pack()
            
            # Row 2: Severity Pie Chart and IP Risk Bar Chart
            chart1_frame = ttk.LabelFrame(self.analytics_frame, text="Vulnerability Severity Distribution", padding=10)
            chart1_frame.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
            
            severity_chart = self.analyzer.create_severity_pie_chart(chart1_frame)
            if severity_chart:
                severity_chart.pack()
            else:
                ttk.Label(chart1_frame, text="No vulnerability data available.\nSearch for CVEs to populate this chart.").pack(pady=20)
            
            chart2_frame = ttk.LabelFrame(self.analytics_frame, text="IP Risk Distribution", padding=10)
            chart2_frame.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)
            
            ip_chart = self.analyzer.create_ip_risk_bar_chart(chart2_frame)
            if ip_chart:
                ip_chart.pack()
            else:
                ttk.Label(chart2_frame, text="No IP reputation data available.\nCheck IPs to populate this chart.").pack(pady=20)
            
            # Row 3: Country Distribution
            chart3_frame = ttk.LabelFrame(self.analytics_frame, text="Geographic Distribution", padding=10)
            chart3_frame.grid(row=2, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
            
            country_chart = self.analyzer.create_country_bar_chart(chart3_frame)
            if country_chart:
                country_chart.pack()
            else:
                ttk.Label(chart3_frame, text="No geographic data available.\nCheck more IPs to populate this chart.").pack(pady=20)
            
            # Row 4: Timeline Chart
            chart4_frame = ttk.LabelFrame(self.analytics_frame, text="Vulnerability Timeline", padding=10)
            chart4_frame.grid(row=3, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
            
            timeline_chart = self.analyzer.create_timeline_chart(chart4_frame)
            if timeline_chart:
                timeline_chart.pack()
            else:
                ttk.Label(chart4_frame, text="No timeline data available.\nSearch for more vulnerabilities to see trends.").pack(pady=20)
            
            # Configure grid weights
            self.analytics_frame.columnconfigure(0, weight=1)
            self.analytics_frame.columnconfigure(1, weight=1)
            
            self.update_status("Analytics refreshed successfully")
            self.log_activity("Analytics charts generated")
            
        except Exception as e:
            logger.error(f"Error refreshing analytics: {e}")
            self.update_status(f"Error generating analytics: {str(e)}")
    
    def export_report(self):
        """Export analysis report"""
        try:
            from tkinter import filedialog
            
            # Generate text report
            report = self.analyzer.generate_summary_report()
            
            # Ask user where to save
            filepath = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Analysis Report"
            )
            
            if filepath:
                with open(filepath, 'w') as f:
                    f.write(report)
                
                self.log_activity(f"Report exported to: {filepath}")
                messagebox.showinfo("Success", f"Report exported to:\n{filepath}")
        
        except Exception as e:
            logger.error(f"Error exporting report: {e}")
            messagebox.showerror("Error", f"Failed to export report:\n{str(e)}")
    
    # === ACTION METHODS ===
    
    def refresh_dashboard(self):
        """Refresh dashboard statistics"""
        try:
            self.update_status("Refreshing dashboard...")
            
            # Get statistics from database
            stats = self.db.get_statistics()
            
            # Update labels
            for key, value in stats.items():
                if key in self.stats_labels:
                    self.stats_labels[key].config(text=str(value))
            
            self.log_activity("Dashboard refreshed")
            self.update_status("Dashboard refreshed successfully")
            
        except Exception as e:
            logger.error(f"Dashboard refresh error: {e}")
            self.update_status(f"Error: {str(e)}")
    
    def search_vulnerabilities(self):
        """Search for vulnerabilities"""
        search_term = self.cve_search_entry.get().strip()
        
        if not search_term:
            messagebox.showwarning("Input Required", "Please enter a search term")
            return
        
        self.update_status(f"Searching for: {search_term}...")
        self.log_activity(f"CVE search: {search_term}")
        
        # Call real NVD API
        results = self.nvd_api.search_cves(keyword=search_term, results_per_page=5)
        
        self.cve_results.config(state='normal')
        self.cve_results.delete('1.0', 'end')
        
        if not results:
            self.cve_results.insert('end', f"No results found for: {search_term}\n\n")
            self.cve_results.insert('end', "Try searching for:\n")
            self.cve_results.insert('end', "- CVE-2024-XXXX (specific CVE ID)\n")
            self.cve_results.insert('end', "- Microsoft, Apache, Linux (vendor names)\n")
        else:
            self.cve_results.insert('end', f"Found {len(results)} vulnerabilities for: {search_term}\n")
            self.cve_results.insert('end', "=" * 60 + "\n\n")
            
            for i, cve in enumerate(results, 1):
                self.cve_results.insert('end', f"[{i}] {cve['cve_id']}\n")
                self.cve_results.insert('end', f"Severity: {cve['severity']} (CVSS: {cve['cvss_score'] or 'N/A'})\n")
                self.cve_results.insert('end', f"Published: {cve['published_date'][:10]}\n")
                self.cve_results.insert('end', f"Description: {cve['description']}\n")
                self.cve_results.insert('end', "-" * 60 + "\n\n")
                
                # Save to database
                self.db.save_vulnerability(cve)
        
        self.cve_results.config(state='disabled')
        self.update_status(f"Found {len(results)} vulnerabilities")
        self.refresh_dashboard()
    
    def check_ip_reputation(self):
        """Check IP reputation"""
        ip_address = self.ip_entry.get().strip()
        
        if not ip_address:
            messagebox.showwarning("Input Required", "Please enter an IP address")
            return
        
        self.update_status(f"Checking IP: {ip_address}...")
        self.log_activity(f"IP reputation check: {ip_address}")
        
        # Call real AbuseIPDB API
        ip_data = self.abuseipdb_api.check_ip(ip_address)
        
        self.ip_results.config(state='normal')
        self.ip_results.delete('1.0', 'end')
        
        # Display formatted report
        report = self.abuseipdb_api.format_report(ip_data)
        self.ip_results.insert('end', report)
        
        self.ip_results.config(state='disabled')
        
        # Save to database if successful
        if "error" not in ip_data:
            self.db.save_ip_reputation(ip_data)
            self.update_status(f"IP check complete - Score: {ip_data.get('abuse_confidence_score', 0)}%")
            self.refresh_dashboard()
        else:
            self.update_status(f"Error: {ip_data['error']}")
    
    def scan_target(self):
        """Scan URL or file hash"""
        target = self.scan_entry.get().strip()
        
        if not target:
            messagebox.showwarning("Input Required", "Please enter a URL or file hash")
            return
        
        self.update_status(f"Scanning: {target}...")
        self.log_activity(f"Scan initiated: {target}")
        
        # Determine if URL or hash
        if target.startswith(('http://', 'https://')):
            scan_data = self.virustotal_api.scan_url(target)
        else:
            # Assume it's a file hash
            scan_data = self.virustotal_api.check_file_hash(target)
        
        self.scan_results.config(state='normal')
        self.scan_results.delete('1.0', 'end')
        
        # Display formatted report
        report = self.virustotal_api.format_scan_report(scan_data)
        self.scan_results.insert('end', report)
        
        self.scan_results.config(state='disabled')
        
        if "error" not in scan_data:
            self.update_status("Scan complete")
            self.refresh_dashboard()
        else:
            self.update_status(f"Error: {scan_data.get('error', 'Unknown error')}")
    
    def search_threat_intel(self):
        """Search threat intelligence"""
        search_term = self.threat_search_entry.get().strip()
        
        if not search_term:
            messagebox.showwarning("Input Required", "Please enter a search term")
            return
        
        self.update_status(f"Searching threat intel for: {search_term}...")
        self.log_activity(f"Threat intel search: {search_term}")
        
        # Call real OTX API
        pulses = self.otx_api.search_pulses(search_term, limit=10)
        
        self.threat_results.config(state='normal')
        self.threat_results.delete('1.0', 'end')
        
        # Display formatted results
        report = self.otx_api.format_pulse_list(pulses)
        self.threat_results.insert('end', report)
        
        self.threat_results.config(state='disabled')
        
        self.update_status(f"Found {len(pulses)} threat pulses")
        if pulses:
            self.refresh_dashboard()
    
    # === UTILITY METHODS ===
    
    def log_activity(self, message):
        """Add message to activity log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {message}\n"
        
        self.activity_log.config(state='normal')
        self.activity_log.insert('end', log_message)
        self.activity_log.see('end')
        self.activity_log.config(state='disabled')
    
    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=f"Status: {message}")
        self.root.update_idletasks()
    
    def show_settings(self):
        """Show settings dialog"""
        messagebox.showinfo("Settings", "Settings dialog coming in Phase 4")
    
    def clear_cache(self):
        """Clear application cache"""
        result = messagebox.askyesno("Clear Cache", "Are you sure you want to clear the cache?")
        if result:
            self.log_activity("Cache cleared")
            messagebox.showinfo("Success", "Cache cleared successfully")
    
    def export_data(self):
        """Export data"""
        messagebox.showinfo("Export", "Data export feature coming in Phase 5")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
CyberSentinel - Threat Intelligence Dashboard
Version 1.0

ITMS 548 - Cybersecurity Technologies
Illinois Institute of Technology

Team:
- Dennis Oseitutu (Project Lead & Lead Developer)
- Akinyemi Aremu (Security Researcher)
- William Smith (Network Security Specialist)

April 2026
        """
        messagebox.showinfo("About CyberSentinel", about_text)
    
    def show_api_guide(self):
        """Show API setup guide"""
        guide_text = """
API Setup Guide:

1. NVD API: https://nvd.nist.gov/developers/request-an-api-key
2. AbuseIPDB: https://www.abuseipdb.com/api
3. VirusTotal: https://www.virustotal.com/gui/join-us
4. AlienVault OTX: https://otx.alienvault.com/api

Add your API keys to: config/config.json
        """
        messagebox.showinfo("API Setup Guide", guide_text)
