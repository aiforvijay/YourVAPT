# VAPT Analysis Tool

A comprehensive Streamlit-based Vulnerability Assessment and Penetration Testing (VAPT) application that guides users through security assessments of Windows 11 and macOS systems.

## Features

- **Multi-OS Support**: Comprehensive command sets for Windows 11 and macOS security assessment
- **Step-by-Step Guidance**: Detailed instructions for running security commands
- **AI-Powered Analysis**: Integration with multiple AI providers (OpenAI, Anthropic, Google Gemini, xAI Grok)
- **Test Mode**: Mock vulnerability analysis without requiring API keys
- **Professional Reports**: Generate PDF, Word, and text reports with CVSS scoring
- **Progress Tracking**: Real-time dashboard showing assessment completion status
- **Compliance Framework**: References to NIST, ISO 27001, and OWASP standards

## Security Assessment Categories

### Windows 11
- 💻 System Information
- 👥 User Management  
- 🔒 Network Security
- 🛡️ Security Software
- ⚠️ Application Security
- 💾 Data Protection
- 📋 Logging and Monitoring
- 🦠 Antivirus & Threat Detection
- 🔥 Firewall Configuration

### macOS
- 💻 System Information
- 👥 User Management
- 🔒 Network Security
- 🛡️ Security Software
- ⚠️ Application Security
- 💾 Data Protection
- 📋 Logging and Monitoring
- 🦠 Antivirus & Threat Detection
- 🔥 Firewall Configuration

## Installation & Setup

### Prerequisites
- Python 3.11 or higher
- pip package manager

### Quick Start

1. **Download the application files:**
   - `app.py` (main application)
   - `.streamlit/config.toml` (configuration)
   - Create empty `data/` folder

2. **Install dependencies:**
   ```bash
   pip install streamlit pandas requests reportlab python-docx openai anthropic google-genai
   ```

3. **Run the application:**
   ```bash
   streamlit run app.py
   ```

### Alternative Installation Methods

#### Option 1: Using Batch Files (Windows)

Create `setup.bat`:
```batch
@echo off
echo Installing Python dependencies for VAPT Analysis...
pip install streamlit pandas requests reportlab python-docx openai anthropic google-genai
echo Setup complete!
pause
```

Create `run.bat`:
```batch
@echo off
echo Starting VAPT Analysis App...
streamlit run app.py
pause
```

#### Option 2: Using Shell Script (Unix/Linux/Mac)

Create `run.sh`:
```bash
#!/bin/bash
echo "Starting VAPT Analysis App..."
streamlit run app.py
```

Make it executable:
```bash
chmod +x run.sh
```

## Project Structure

```
vapt-analysis/
├── app.py                 # Main application file
├── .streamlit/
│   └── config.toml        # Streamlit configuration
├── data/                  # Temporary data storage (auto-created)
├── setup.bat             # Windows setup script (optional)
├── run.bat               # Windows run script (optional)
├── run.sh                # Unix run script (optional)
└── README.md             # This file
```

## Usage Guide

### 1. Launch the Application
- Run `streamlit run app.py` or use the batch/shell scripts
- Open your browser to `http://localhost:8501`

### 2. Configure API Keys (Optional)
- Add API keys for AI analysis in the configuration section
- Supported providers: OpenAI, Anthropic, Google Gemini, xAI Grok
- Test mode available without API keys

### 3. Select Target Operating System
- Choose between Windows 11 and macOS tabs
- Each OS has 9 security assessment categories

### 4. Run Security Commands
- Follow step-by-step instructions for each command
- Copy command outputs and paste into the provided text areas
- Use keyboard shortcuts provided for quick access

### 5. Analyze Results
- **Test Run**: Uses simulated vulnerability data
- **AI Run**: Sends outputs to AI for real-time analysis (requires API key)
- Results include risk levels, CVSS scores, and remediation steps

### 6. Generate Reports
- Fill in auditor details (name, certification, organization)
- Choose report format: PDF, Word Document, or Text
- Reports include comprehensive analysis and compliance references

## API Key Setup

### OpenAI (ChatGPT)
1. Visit https://platform.openai.com/
2. Create account and generate API key
3. Add key to the application interface

### Anthropic (Claude)
1. Visit https://console.anthropic.com/
2. Create account and generate API key
3. Add key to the application interface

### Google Gemini
1. Visit https://ai.google.dev/
2. Create API key through Google AI Studio
3. Add key to the application interface

### xAI (Grok)
1. Visit https://x.ai/
2. Create account and generate API key
3. Add key to the application interface

## Report Features

### PDF Reports
- Professional formatting with tables and sections
- Risk level color coding
- CVSS scoring and CVE references
- Compliance framework mapping (NIST, ISO 27001, OWASP)

### Word Documents
- Structured document with headings and sections
- Easy to edit and customize
- Corporate-friendly format

### Text Reports
- Simple plain text format
- Easy to integrate with other tools
- Lightweight and portable

## Security Notice

⚠️ **Important**: This tool is designed for authorized security assessments only. Ensure you have proper authorization before running these commands on any system.

## Compliance & Standards

This tool references industry-standard security frameworks:
- **NIST SP 800-53**: Security controls framework
- **ISO 27001**: Information security management standards  
- **OWASP Top 10**: Web application security risks
- **CVSS**: Common Vulnerability Scoring System

## Troubleshooting

### Common Issues

1. **Import errors**: Ensure all dependencies are installed
   ```bash
   pip install --upgrade streamlit pandas requests reportlab python-docx openai anthropic google-genai
   ```

2. **Port already in use**: Change the port in `.streamlit/config.toml`
   ```toml
   [server]
   port = 8502
   ```

3. **AI analysis not working**: Verify API key is correctly entered and account has sufficient credits

### System Requirements

- Python 3.11+
- 2GB RAM minimum
- Internet connection for AI analysis
- Web browser (Chrome, Firefox, Safari, Edge)

## License

This tool is provided for educational and authorized security assessment purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Verify all dependencies are correctly installed
3. Ensure you have proper authorization for security assessments

---

**Disclaimer**: This tool provides guidance for vulnerability assessment. Results should be verified by qualified security professionals.
