#!/usr/bin/env node

/**
 * Markdown Sanitizer for TITAN Security Reports
 * Fixes code block formatting, line breaks, and content issues
 */

const fs = require('fs');
const path = require('path');

// Simple markdown sanitizer without external dependencies
class MarkdownSanitizer {
  constructor() {
    this.codeBlockRegex = /```(\w*)\n?([\s\S]*?)```/g;
    this.inlineCodeRegex = /`([^`]+)`/g;
  }

  /**
   * Sanitize markdown content
   */
  sanitize(content) {
    let sanitized = content;

    // Fix code blocks - ensure proper line breaks
    sanitized = this.fixCodeBlocks(sanitized);
    
    // Fix inline code formatting
    sanitized = this.fixInlineCode(sanitized);
    
    // Fix line breaks and spacing
    sanitized = this.fixLineBreaks(sanitized);
    
    // Remove excessive whitespace
    sanitized = this.normalizeWhitespace(sanitized);
    
    // Fix list formatting
    sanitized = this.fixListFormatting(sanitized);

    return sanitized;
  }

  /**
   * Fix code block formatting issues
   */
  fixCodeBlocks(content) {
    return content.replace(this.codeBlockRegex, (match, language, code) => {
      // Clean up the code content
      let cleanCode = code
        .replace(/\\n/g, '\n')           // Fix escaped newlines
        .replace(/\\t/g, '    ')         // Fix escaped tabs
        .replace(/\\"/g, '"')            // Fix escaped quotes
        .replace(/\\'/g, "'")            // Fix escaped single quotes
        .replace(/\\\\/g, '\\')          // Fix escaped backslashes
        .trim();                         // Remove leading/trailing whitespace

      // Ensure proper line breaks in code
      cleanCode = this.normalizeCodeLines(cleanCode);

      // Return properly formatted code block
      return `\`\`\`${language || ''}\n${cleanCode}\n\`\`\``;
    });
  }

  /**
   * Normalize code lines - handle long lines and formatting
   */
  normalizeCodeLines(code) {
    const lines = code.split('\n');
    return lines
      .map(line => {
        // Trim excessive whitespace but preserve indentation
        return line.replace(/\s+$/, '').replace(/^\s{8,}/, match => {
          // Limit excessive indentation to 8 spaces max
          return '        ';
        });
      })
      .join('\n');
  }

  /**
   * Fix inline code formatting
   */
  fixInlineCode(content) {
    return content.replace(this.inlineCodeRegex, (match, code) => {
      // Clean up inline code
      const cleanCode = code
        .replace(/\\"/g, '"')
        .replace(/\\'/g, "'")
        .trim();
      
      return `\`${cleanCode}\``;
    });
  }

  /**
   * Fix line breaks and spacing issues
   */
  fixLineBreaks(content) {
    return content
      // Fix multiple consecutive line breaks
      .replace(/\n{4,}/g, '\n\n\n')
      // Ensure proper spacing around headers
      .replace(/^(#{1,6}\s+.+)$/gm, '\n$1\n')
      // Ensure proper spacing around horizontal rules
      .replace(/^---$/gm, '\n---\n')
      // Fix spacing around list items
      .replace(/^(\s*[-*+]\s+)/gm, '\n$1');
  }

  /**
   * Normalize whitespace throughout the document
   */
  normalizeWhitespace(content) {
    return content
      // Remove trailing spaces
      .replace(/[ \t]+$/gm, '')
      // Normalize multiple spaces to single spaces (except in code blocks)
      .replace(/(?<!```[\s\S]*?)[ ]{2,}(?![\s\S]*?```)/g, ' ')
      // Remove excessive blank lines at start/end
      .replace(/^\n+/, '')
      .replace(/\n+$/, '\n');
  }

  /**
   * Fix list formatting issues
   */
  fixListFormatting(content) {
    return content
      // Ensure consistent list markers
      .replace(/^(\s*)[-*+](\s+)/gm, '$1- $2')
      // Fix nested list indentation
      .replace(/^(\s{2,})- /gm, (match, spaces) => {
        const level = Math.floor(spaces.length / 2);
        return '  '.repeat(level) + '- ';
      });
  }

  /**
   * Specific cleanup for security report formatting
   */
  cleanSecurityReport(content) {
    let cleaned = content;

    // Fix vulnerability headers
    cleaned = cleaned.replace(/^### (🚨|✅|❌) (.+)$/gm, '### $1 $2\n');

    // Fix analysis field formatting - handle long analysis text
    cleaned = cleaned.replace(/^- \*\*Analysis:\*\* (.+)$/gm, (match, analysis) => {
      if (analysis.length > 150) {
        // Break long analysis into readable chunks
        const words = analysis.split(' ');
        const lines = [];
        let currentLine = '';
        
        for (const word of words) {
          if ((currentLine + word).length > 80) {
            if (currentLine) lines.push(currentLine.trim());
            currentLine = word + ' ';
          } else {
            currentLine += word + ' ';
          }
        }
        if (currentLine) lines.push(currentLine.trim());
        
        return '- **Analysis:** ' + lines.join('\n  ');
      }
      return match;
    });

    return cleaned;
  }
}

// CLI interface
function main() {
  const args = process.argv.slice(2);
  
  if (args.length < 1) {
    console.error('Usage: node sanitize-markdown.js <input-file> [output-file]');
    console.error('       If output-file is not provided, input file will be overwritten');
    process.exit(1);
  }

  const inputFile = args[0];
  const outputFile = args[1] || inputFile;

  if (!fs.existsSync(inputFile)) {
    console.error(`Error: Input file '${inputFile}' does not exist`);
    process.exit(1);
  }

  try {
    console.log(`Sanitizing markdown file: ${inputFile}`);
    
    const content = fs.readFileSync(inputFile, 'utf8');
    const sanitizer = new MarkdownSanitizer();
    
    let sanitized = sanitizer.sanitize(content);
    
    // Apply security report specific cleaning if this looks like a security report
    if (content.includes('TITAN Security Scan Report') || content.includes('Vulnerability Found')) {
      sanitized = sanitizer.cleanSecurityReport(sanitized);
    }
    
    fs.writeFileSync(outputFile, sanitized, 'utf8');
    
    console.log(`✅ Sanitized markdown saved to: ${outputFile}`);
    
    // Show statistics
    const originalLines = content.split('\n').length;
    const sanitizedLines = sanitized.split('\n').length;
    const originalSize = Buffer.byteLength(content, 'utf8');
    const sanitizedSize = Buffer.byteLength(sanitized, 'utf8');
    
    console.log(`📊 Statistics:`);
    console.log(`   Lines: ${originalLines} → ${sanitizedLines} (${sanitizedLines - originalLines > 0 ? '+' : ''}${sanitizedLines - originalLines})`);
    console.log(`   Size: ${originalSize} → ${sanitizedSize} bytes (${sanitizedSize - originalSize > 0 ? '+' : ''}${sanitizedSize - originalSize})`);
    
  } catch (error) {
    console.error(`Error sanitizing markdown: ${error.message}`);
    process.exit(1);
  }
}

// Export for use as module
module.exports = MarkdownSanitizer;

// Run CLI if called directly
if (require.main === module) {
  main();
}