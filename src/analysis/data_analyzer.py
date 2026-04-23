"""
Data Analysis and Visualization Module
Generates charts and graphs from threat intelligence data
"""

import matplotlib
matplotlib.use('TkAgg')  # Use TkAgg backend for Tkinter integration
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from datetime import datetime
import logging
from collections import Counter

logger = logging.getLogger("cybersentinel")

class DataAnalyzer:
    """Analyzes and visualizes threat intelligence data"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        logger.info("Data Analyzer initialized")
    
    def get_vulnerability_severity_distribution(self):
        """
        Get distribution of vulnerability severities
        
        Returns:
            Dictionary with severity counts
        """
        try:
            vulns = self.db.execute_query("SELECT severity FROM vulnerabilities")
            
            if not vulns:
                return {}
            
            severities = [v['severity'] for v in vulns if v['severity']]
            severity_counts = Counter(severities)
            
            return dict(severity_counts)
            
        except Exception as e:
            logger.error(f"Error getting severity distribution: {e}")
            return {}
    
    def get_cvss_score_distribution(self):
        """
        Get distribution of CVSS scores
        
        Returns:
            List of CVSS scores
        """
        try:
            vulns = self.db.execute_query(
                "SELECT cvss_score FROM vulnerabilities WHERE cvss_score IS NOT NULL"
            )
            
            scores = [v['cvss_score'] for v in vulns]
            return scores
            
        except Exception as e:
            logger.error(f"Error getting CVSS distribution: {e}")
            return []
    
    def get_ip_reputation_distribution(self):
        """
        Get distribution of IP abuse confidence scores
        
        Returns:
            Dictionary with risk level counts
        """
        try:
            ips = self.db.execute_query(
                "SELECT abuse_confidence_score FROM ip_reputation"
            )
            
            if not ips:
                return {}
            
            # Categorize scores
            categories = {
                'Low Risk (0-25%)': 0,
                'Medium Risk (26-74%)': 0,
                'High Risk (75-100%)': 0
            }
            
            for ip in ips:
                score = ip['abuse_confidence_score']
                if score <= 25:
                    categories['Low Risk (0-25%)'] += 1
                elif score <= 74:
                    categories['Medium Risk (26-74%)'] += 1
                else:
                    categories['High Risk (75-100%)'] += 1
            
            return categories
            
        except Exception as e:
            logger.error(f"Error getting IP distribution: {e}")
            return {}
    
    def get_country_distribution(self):
        """
        Get distribution of IPs by country
        
        Returns:
            Dictionary with country counts
        """
        try:
            ips = self.db.execute_query(
                "SELECT country_code FROM ip_reputation WHERE country_code IS NOT NULL"
            )
            
            countries = [ip['country_code'] for ip in ips]
            country_counts = Counter(countries)
            
            # Get top 10 countries
            top_countries = dict(country_counts.most_common(10))
            return top_countries
            
        except Exception as e:
            logger.error(f"Error getting country distribution: {e}")
            return {}
    
    def get_vulnerability_timeline(self):
        """
        Get vulnerability counts over time
        
        Returns:
            Dictionary with dates and counts
        """
        try:
            vulns = self.db.execute_query(
                "SELECT published_date FROM vulnerabilities WHERE published_date IS NOT NULL"
            )
            
            if not vulns:
                return {}
            
            # Extract year-month from dates
            dates = []
            for v in vulns:
                try:
                    date_str = v['published_date'][:7]  # YYYY-MM
                    dates.append(date_str)
                except:
                    pass
            
            date_counts = Counter(dates)
            # Sort by date
            sorted_dates = dict(sorted(date_counts.items()))
            
            return sorted_dates
            
        except Exception as e:
            logger.error(f"Error getting vulnerability timeline: {e}")
            return {}
    
    def create_severity_pie_chart(self, parent_frame):
        """
        Create pie chart of vulnerability severities
        
        Args:
            parent_frame: Tkinter frame to embed chart
            
        Returns:
            Canvas with chart
        """
        try:
            data = self.get_vulnerability_severity_distribution()
            
            if not data:
                return None
            
            fig, ax = plt.subplots(figsize=(6, 4))
            
            colors = {
                'CRITICAL': '#d32f2f',
                'HIGH': '#f57c00',
                'MEDIUM': '#fbc02d',
                'LOW': '#388e3c',
                'UNKNOWN': '#757575'
            }
            
            chart_colors = [colors.get(k, '#757575') for k in data.keys()]
            
            ax.pie(
                data.values(),
                labels=data.keys(),
                autopct='%1.1f%%',
                colors=chart_colors,
                startangle=90
            )
            ax.set_title('Vulnerability Severity Distribution', fontsize=12, fontweight='bold')
            
            canvas = FigureCanvasTkAgg(fig, parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget()
            
        except Exception as e:
            logger.error(f"Error creating severity chart: {e}")
            return None
    
    def create_ip_risk_bar_chart(self, parent_frame):
        """
        Create bar chart of IP risk distribution
        
        Args:
            parent_frame: Tkinter frame to embed chart
            
        Returns:
            Canvas with chart
        """
        try:
            data = self.get_ip_reputation_distribution()
            
            if not data:
                return None
            
            fig, ax = plt.subplots(figsize=(6, 4))
            
            colors = ['#388e3c', '#fbc02d', '#d32f2f']
            
            bars = ax.bar(data.keys(), data.values(), color=colors)
            ax.set_title('IP Address Risk Distribution', fontsize=12, fontweight='bold')
            ax.set_ylabel('Number of IPs')
            ax.set_xlabel('Risk Level')
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax.text(
                    bar.get_x() + bar.get_width()/2.,
                    height,
                    f'{int(height)}',
                    ha='center',
                    va='bottom'
                )
            
            plt.xticks(rotation=15, ha='right')
            plt.tight_layout()
            
            canvas = FigureCanvasTkAgg(fig, parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget()
            
        except Exception as e:
            logger.error(f"Error creating IP risk chart: {e}")
            return None
    
    def create_country_bar_chart(self, parent_frame):
        """
        Create bar chart of top countries by malicious IPs
        
        Args:
            parent_frame: Tkinter frame to embed chart
            
        Returns:
            Canvas with chart
        """
        try:
            data = self.get_country_distribution()
            
            if not data:
                return None
            
            fig, ax = plt.subplots(figsize=(6, 4))
            
            ax.barh(list(data.keys()), list(data.values()), color='#2196f3')
            ax.set_title('Top Countries by IP Checks', fontsize=12, fontweight='bold')
            ax.set_xlabel('Number of IPs Checked')
            ax.set_ylabel('Country Code')
            
            plt.tight_layout()
            
            canvas = FigureCanvasTkAgg(fig, parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget()
            
        except Exception as e:
            logger.error(f"Error creating country chart: {e}")
            return None
    
    def create_timeline_chart(self, parent_frame):
        """
        Create line chart of vulnerabilities over time
        
        Args:
            parent_frame: Tkinter frame to embed chart
            
        Returns:
            Canvas with chart
        """
        try:
            data = self.get_vulnerability_timeline()
            
            if not data:
                return None
            
            fig, ax = plt.subplots(figsize=(8, 4))
            
            dates = list(data.keys())
            counts = list(data.values())
            
            ax.plot(dates, counts, marker='o', linewidth=2, markersize=6, color='#2196f3')
            ax.fill_between(range(len(dates)), counts, alpha=0.3, color='#2196f3')
            
            ax.set_title('Vulnerability Timeline', fontsize=12, fontweight='bold')
            ax.set_xlabel('Date (Year-Month)')
            ax.set_ylabel('Number of Vulnerabilities')
            ax.grid(True, alpha=0.3)
            
            # Show only every nth label to avoid crowding
            n = max(1, len(dates) // 10)
            ax.set_xticks(range(0, len(dates), n))
            ax.set_xticklabels([dates[i] for i in range(0, len(dates), n)], rotation=45, ha='right')
            
            plt.tight_layout()
            
            canvas = FigureCanvasTkAgg(fig, parent_frame)
            canvas.draw()
            
            return canvas.get_tk_widget()
            
        except Exception as e:
            logger.error(f"Error creating timeline chart: {e}")
            return None
    
    def generate_summary_report(self):
        """
        Generate text summary of all data
        
        Returns:
            String with formatted report
        """
        try:
            stats = self.db.get_statistics()
            severity_dist = self.get_vulnerability_severity_distribution()
            ip_dist = self.get_ip_reputation_distribution()
            country_dist = self.get_country_distribution()
            
            report = []
            report.append("=" * 60)
            report.append("CYBERSENTINEL DATA ANALYSIS REPORT")
            report.append("=" * 60)
            report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append("")
            
            report.append("OVERALL STATISTICS:")
            report.append(f"  Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
            report.append(f"  Total IP Checks: {stats.get('total_ip_checks', 0)}")
            report.append(f"  Total Scans: {stats.get('total_scans', 0)}")
            report.append(f"  Total Threat Pulses: {stats.get('total_threat_pulses', 0)}")
            report.append("")
            
            if severity_dist:
                report.append("VULNERABILITY SEVERITY BREAKDOWN:")
                for severity, count in severity_dist.items():
                    report.append(f"  {severity}: {count}")
                report.append("")
            
            if ip_dist:
                report.append("IP RISK DISTRIBUTION:")
                for risk, count in ip_dist.items():
                    report.append(f"  {risk}: {count}")
                report.append("")
            
            if country_dist:
                report.append("TOP COUNTRIES (IP Checks):")
                for country, count in list(country_dist.items())[:5]:
                    report.append(f"  {country}: {count}")
                report.append("")
            
            report.append("=" * 60)
            
            return "\n".join(report)
            
        except Exception as e:
            logger.error(f"Error generating summary report: {e}")
            return "Error generating report"
    
    def export_to_csv(self, filepath):
        """
        Export all data to CSV file
        
        Args:
            filepath: Path to save CSV file
            
        Returns:
            Boolean success status
        """
        try:
            # Get all vulnerabilities
            vulns = self.db.execute_query("SELECT * FROM vulnerabilities")
            
            if vulns:
                df = pd.DataFrame(vulns)
                df.to_csv(filepath, index=False)
                logger.info(f"Data exported to {filepath}")
                return True
            else:
                logger.warning("No data to export")
                return False
                
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False
