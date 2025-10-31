"""
Simple launcher for SlothShield Dashboard
"""

import os
import sys

print("="*80)
print("  🛡️ SlothShield - Slowloris Attack Detection Dashboard")
print("="*80)
print()
print("Starting dashboard...")
print("Dashboard will open in your browser at: http://localhost:8501")
print()
print("Press Ctrl+C to stop the dashboard")
print("="*80)
print()

os.system("streamlit run slothshield_dashboard.py")
