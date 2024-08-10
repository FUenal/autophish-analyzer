"""
AutoPhish Analyzer
Author: Fatih Uenal, PhD
Version: 1.0
Date: 10.08.2024
"""

## import modules
import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from forms import UploadForm
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
from bs4 import BeautifulSoup
from eml_analysis import EmailAnalyzer

## initiate Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'

## create upload and results folders if they don`t exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if not os.path.exists(app.config['RESULTS_FOLDER']):
    os.makedirs(app.config['RESULTS_FOLDER'])

## function to create PDF file from analysis results
def create_pdf(result, metadata, pdf_filepath):
    doc = SimpleDocTemplate(pdf_filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add title to PDF
    elements.append(Paragraph("AutoPhish Analyzer Results", styles['Title']))

    # Add summary to PDF
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Summary", styles['Heading2']))
    summary_text = f"""
    <b>Total Malicious URLs:</b> {metadata['total_malicious']}<br/>
    <b>Total Suspicious URLs:</b> {metadata['total_suspicious']}<br/>
    <b>Total Clean URLs:</b> {metadata['total_urls'] - metadata['total_malicious'] - metadata['total_suspicious']}
    """
    elements.append(Paragraph(summary_text, styles['Normal']))

    # Add email header/content analysis to PDF
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Email Header/Content Analysis", styles['Heading2']))
    header_analysis_text = f"""
    <b>SPF and DKIM Authentication Results:</b> {metadata['auth_results']}<br/>
    <b>Sender IP Address:</b> {metadata['ip_address']}<br/>
    <b>Reverse DNS:</b> {metadata['domain_name']}<br/>
    <b>From Email Address:</b> {metadata['from_address']}<br/>
    <b>Return Path Email Address:</b> {metadata['return_path']}<br/>
    <b>Subject Line:</b> {metadata['subject']}<br/>
    <b>Recipient Email Addresses:</b> {metadata['recipients']}<br/>
    <b>Cc Email Addresses:</b> {metadata['cc_addresses']}<br/>
    <b>Date:</b> {metadata['date']}<br/>
    <b>Reply to:</b> {metadata['reply_to']}<br/>
    <b>URLs:</b> {'<br/>'.join(metadata['urls'])}
    """
    elements.append(Paragraph(header_analysis_text, styles['Normal']))

    # Add VirusTotal URL check results to PDF
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("VirusTotal URL Check Results", styles['Heading2']))

    # Parse the result HTML to extract table data
    soup = BeautifulSoup(result, 'html.parser')
    for div in soup.find_all("div"):
        heading = div.find("h3")
        if heading:
            elements.append(Spacer(1, 12))
            elements.append(Paragraph(heading.get_text(), styles['Heading3']))

            paragraphs = div.find_all("p")
            for paragraph in paragraphs:
                elements.append(Paragraph(paragraph.get_text(), styles['Normal']))

            table = div.find("table")
            if table:
                table_data = []
                headers = [th.get_text() for th in table.find_all("th")]
                if headers:
                    table_data.append(headers)

                rows = table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    row_data = []
                    row_color = colors.black  # Default row color

                    for col in cols:
                        text = col.get_text()
                        if "malicious" in text.lower() or "suspicious" in text.lower() or "phishing" in text.lower():
                            row_color = colors.red
                        row_data.append(text)

                    if row_data:
                        table_data.append(row_data)

                if table_data:
                    # Create a table with column titles and adjust column widths
                    col_widths = [2 * inch, 1.5 * inch, 2 * inch]  # Set column widths
                    table = Table(table_data, colWidths=col_widths)
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.white),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),  # Adjust font size to fit content
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 2),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 2),
                    ]))

                    # Apply color to rows based on row_color logic
                    for row_num, row in enumerate(table_data[1:], start=1):  # Skip header row
                        if any("malicious" in cell.lower() or "suspicious" in cell.lower() or "phishing" in cell.lower() for cell in row):
                            table.setStyle(TableStyle([('TEXTCOLOR', (0, row_num), (-1, row_num), colors.red)]))
                        else:
                            table.setStyle(TableStyle([('TEXTCOLOR', (0, row_num), (-1, row_num), colors.black)]))

                    elements.append(table)

    # Add attachment check results to PDF
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Attachment Check Results", styles['Heading2']))

    # Extract attachment results from the parsed HTML
    attachment_results = soup.find_all("div", class_="attachment")
    for attachment in attachment_results:
        paragraphs = attachment.find_all("p")
        for paragraph in paragraphs:
            text = paragraph.get_text()
            color = colors.green if "File not found" in text or "clean" in text.lower() else colors.red
            style = styles['Normal'].clone('attachment_style')
            style.textColor = color
            elements.append(Paragraph(text, style))

        table = attachment.find("table")
        if table:
            table_data = []
            headers = [th.get_text() for th in table.find_all("th")]
            if headers:
                table_data.append(headers)

            rows = table.find_all("tr")
            for row in rows:
                cols = row.find_all("td")
                row_data = []
                row_color = colors.black  # Default row color

                for col in cols:
                    text = col.get_text()
                    if "malicious" in text.lower() or "suspicious" in text.lower() or "phishing" in text.lower():
                        row_color = colors.red
                    row_data.append(text)

                if row_data:
                    table_data.append(row_data)

            if table_data:
                # Create a table with column titles and adjust column widths
                col_widths = [2 * inch, 1.5 * inch, 2 * inch]  # Set column widths
                table = Table(table_data, colWidths=col_widths)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.white),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),  # Adjust font size to fit content
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 2),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 2),
                ]))

                # Apply color to rows based on row_color logic
                for row_num, row in enumerate(table_data[1:], start=1):  # Skip header row
                    if any("malicious" in cell.lower() or "suspicious" in cell.lower() or "phishing" in cell.lower() for cell in row):
                        table.setStyle(TableStyle([('TEXTCOLOR', (0, row_num), (-1, row_num), colors.red)]))
                    else:
                        table.setStyle(TableStyle([('TEXTCOLOR', (0, row_num), (-1, row_num), colors.black)]))

                elements.append(table)

    # Build PDF document
    doc.build(elements)

## route for index page
@app.route('/', methods=['GET', 'POST'])
def index():
    form = UploadForm()
    if form.validate_on_submit():
        eml_file = form.eml_file.data
        filename = secure_filename(eml_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        eml_file.save(filepath)
        
        with open(filepath, 'r', encoding='utf-8', errors='replace') as file:
            eml_content = file.read()
        
        analyzer = EmailAnalyzer(eml_content)
        analysis_result, metadata = analyzer.analyze()

        # save analysis result as a PDF file
        pdf_filename = f"{metadata['subject']}_{metadata['from_address']}_{metadata['analysis_time']}.pdf"
        pdf_filepath = os.path.join(app.config['RESULTS_FOLDER'], pdf_filename)
        create_pdf(analysis_result, metadata, pdf_filepath)
        
        # render results template with analysis results
        return render_template('results.html', result=analysis_result, metadata=metadata, pdf_filename=pdf_filename)
    
    # render index template with upload form
    return render_template('index.html', form=form)

## route to download results PDF file
@app.route('/results/<filename>')
def results(filename):
    return send_from_directory(app.config['RESULTS_FOLDER'], filename)

## run Flask
if __name__ == '__main__':
    app.run(debug=True)
