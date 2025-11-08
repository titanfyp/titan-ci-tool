# TITAN Repository Security Scan Tool

This tool automates security scanning of your repository using the TITAN API with Server-Sent Events (SSE) for real-time progress updates. It connects to the TITAN chat endpoint to analyze your code and generate comprehensive security reports with enhanced reliability and timeout protection.

## How It Works
- Connects to the TITAN SSE endpoint (`/chat?stream=true`) with your repository URL and GitHub authentication token
- Receives real-time progress updates via Server-Sent Events with enhanced error handling
- Processes findings data directly from the SSE stream with timeout protection
- Generates detailed security reports in multiple formats with improved content parsing
- Provides configurable security policy enforcement with report preservation
- Always generates reports as artifacts, even when builds fail due to policy violations
- Uses GitHub token authentication for secure repository access by the TITAN API

## Setup
1. **Add the Tool to Your Repository**
   - Copy the contents of the `titan-ci-tool` folder into your repository.

2. **Configure Your API Settings**
   - Set up your API base URL as a GitHub secret or environment variable.

3. **GitHub Token Authentication**
   - The tool requires a GitHub token to allow the TITAN API to access your repository for analysis.
   - Use `${{ secrets.GH_TOKEN }}` which is automatically provided by GitHub Actions with read access to your repository.
   - No manual configuration needed - GitHub Actions provides this token automatically.

## Publishing as a Reusable GitHub Action

This tool can be published as a reusable GitHub Action. To do so:

1. Ensure your repository contains the `titan-ci-tool` folder with `action.yml`, `entrypoint.sh`, and other required files.
2. Push your repository to GitHub (public or private).
3. Reference the action in your workflow using the `uses:` syntax.

### Inputs
- `api_base_url` (required): URL for the backend API
- `github_token` (required): GitHub token for repository access. Use `${{ secrets.GH_TOKEN }}` which is automatically provided by GitHub Actions
- `report_format` (optional): The report output format type (md|pdf|xml). Default: md
- `timeout_seconds` (optional): Timeout to call the API before failing (in seconds). Default: 300
- `exclude_files` (optional): Comma-separated list of file patterns to exclude from scanning (glob)
- `blocking` (optional): Whether this step is blocking (fail on issues) or non-blocking. Default: true
- `block_percentage` (optional): Percentage of files with issues required to block. Default: 50

## Output
- The scan results are saved in the specified format (`security_report.md`, `security_report.pdf`, or `security_report.xml`).
- **Enhanced Formatting**: All formats include risk assessment, detailed findings, and actionable recommendations
- **Auto-Sanitization**: Markdown reports are automatically cleaned for proper code block formatting and line breaks
- **Markdown**: Clean formatting with emoji icons, tables, and sections
- **PDF**: Professional layout with Chrome/Chromium headless conversion and 30-second timeout protection
- **XML**: Structured format for tool integration and automated processing
- **Report Preservation**: Security reports are always generated and uploaded as artifacts, even when builds fail
- **Policy Enforcement**: If blocking mode is enabled and issues exceed the threshold, the step will fail AFTER generating reports
- **Enhanced Reliability**: SSE connection with 60-second timeout protection and improved error handling
- Detailed logs show which files are scanned and any issues found.

## Customization
- The tool connects to a single SSE endpoint: `/chat?stream=true` for real-time scan progress
- Sends repository URL and GitHub token in the request body as `{"content": "github_url", "github_token": "token"}`
- The GitHub token is used by the TITAN API to securely access and analyze your repository
- Processes findings data directly from SSE events with enhanced timeout protection (60 seconds)
- **PDF generation** uses Go-based md2pdf for fast and reliable conversion
- **Simple executable** single binary with no complex dependencies or setup
- **Markdown sanitization** automatically fixes code block formatting, line breaks, and content issues
- **Report formats** include professional styling and detailed vulnerability analysis
- **XML output** provides structured data for integration with security tools and CI/CD pipelines
- **Enhanced Error Handling** with detailed logging and robust PDF generation

## Report Features

### Markdown Format (md)
- 🛡️ Professional header with emoji icons
- 📊 Summary table with scan metrics
- 📁 Detailed findings section
- 🔍 Configuration overview
- ✨ Auto-sanitized code blocks and line breaks
- 🧹 Normalized whitespace and formatting
- Clean, readable formatting for GitHub/GitLab

### PDF Format (pdf) 
- Executive summary with risk assessment  
- Clean markdown-to-PDF conversion using Go-based md2pdf
- Professional document layout and formatting
- Fast and reliable conversion with solworktech/md2pdf
- Single binary executable with no complex dependencies
- Requires Go runtime for installation
- Simple and efficient conversion process

### XML Format (xml)
- Structured data format for tool integration
- Machine-readable findings and metadata
- CDATA sections for safe content handling
- Suitable for CI/CD pipeline automation
- Easy parsing for security dashboards

## Example Usage

```yaml
- name: Run TITAN Security Scan
  uses: titanfyp/titan-ci-tool@<VERSION>
  with:
    api_base_url: ${{ secrets.TITAN_API_BASE_URL }}
    github_token: ${{ secrets.GH_TOKEN }}
    report_format: 'pdf'
    timeout_seconds: 600
    blocking: true
    block_percentage: 25

- name: Security scan summary
  if: failure()
  run: |
    echo "Security scan completed but found vulnerabilities above threshold"
    echo "Review the security report to identify and fix the issues"

- name: Upload security report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: security_report.*
    retention-days: 30
```

Example of repository using the tool: https://github.com/syahmiabbas/vulnerable-rest

- Replace `<VERSION>` with the version release from TITAN

The configuration will:
- Generate a professional PDF report with risk assessment and enhanced timeout protection
- Set a 10-minute timeout for SSE connection with automatic retry handling
- Exclude common build artifacts and tool directories from scanning
- **Always generate and upload security reports**, even when builds fail
- Block the pipeline if 25% or more of files have issues (after generating reports)
- Provide clear feedback on security policy violations with detailed messaging
