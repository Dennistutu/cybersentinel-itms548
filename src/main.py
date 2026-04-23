#!/usr/bin/env python3
"""
CyberSentinel - Threat Intelligence Dashboard
Main application entry point

ITMS 548 - Cybersecurity Technologies
Illinois Institute of Technology
Team: Dennis Oseitutu, Akinyemi Aremu, William Smith
"""

import sys
import tkinter as tk
from tkinter import messagebox
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

from gui.main_window import CyberSentinelApp
from database.db_manager import DatabaseManager
from utils.logger import setup_logger

def main():
    """Main application entry point"""
    
    # Setup logging
    logger = setup_logger()
    logger.info("=" * 60)
    logger.info("CyberSentinel - Threat Intelligence Dashboard")
    logger.info("=" * 60)
    
    try:
        # Initialize database
        logger.info("Initializing database...")
        db = DatabaseManager()
        db.initialize()
        logger.info("Database initialized successfully")
        
        # Create and run GUI application
        logger.info("Starting GUI application...")
        root = tk.Tk()
        app = CyberSentinelApp(root)
        
        logger.info("Application started successfully")
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        messagebox.showerror(
            "Fatal Error",
            f"CyberSentinel encountered a fatal error:\n\n{str(e)}\n\nCheck logs for details."
        )
        sys.exit(1)
    
    finally:
        logger.info("Application shutdown")

if __name__ == "__main__":
    main()
