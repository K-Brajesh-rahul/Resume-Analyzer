import os
import re
import json
import sqlite3
from datetime import datetime
import PyPDF2
import docx
from collections import Counter

# Common skills database (you can expand this)
TECHNICAL_SKILLS = {
    'programming_languages': [
        'python', 'java', 'javascript', 'c++', 'c#', 'php', 'ruby', 'go', 'rust', 'swift',
        'kotlin', 'scala', 'r', 'matlab', 'sql', 'html', 'css', 'typescript', 'dart'
    ],
    'frameworks': [
        'react', 'angular', 'vue', 'django', 'flask', 'spring', 'express', 'laravel',
        'rails', 'asp.net', 'bootstrap', 'jquery', 'node.js', 'next.js', 'nuxt.js'
    ],
    'databases': [
        'mysql', 'postgresql', 'mongodb', 'sqlite', 'redis', 'oracle', 'sql server',
        'cassandra', 'elasticsearch', 'firebase', 'dynamodb'
    ],
    'tools': [
        'git', 'docker', 'kubernetes', 'jenkins', 'aws', 'azure', 'gcp', 'linux',
        'windows', 'macos', 'jira', 'confluence', 'slack', 'trello', 'figma', 'photoshop'
    ],
    'data_science': [
        'machine learning', 'deep learning', 'tensorflow', 'pytorch', 'scikit-learn',
        'pandas', 'numpy', 'matplotlib', 'seaborn', 'jupyter', 'tableau', 'power bi'
    ]
}

# Flatten all skills into one list for easier searching
ALL_SKILLS = []
for category in TECHNICAL_SKILLS.values():
    ALL_SKILLS.extend(category)

def extract_text_from_pdf(file_path):
    """Extract text from PDF file"""
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
        return text.strip()
    except Exception as e:
        print(f"Error extracting PDF: {e}")
        return None

def extract_text_from_docx(file_path):
    """Extract text from DOCX file"""
    try:
        doc = docx.Document(file_path)
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text.strip()
    except Exception as e:
        print(f"Error extracting DOCX: {e}")
        return None

def extract_text_from_txt(file_path):
    """Extract text from TXT file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read().strip()
    except Exception as e:
        print(f"Error extracting TXT: {e}")
        return None

def extract_text_from_file(file_path):
    """Extract text from various file formats"""
    file_extension = os.path.splitext(file_path)[1].lower()
    
    if file_extension == '.pdf':
        return extract_text_from_pdf(file_path)
    elif file_extension == '.docx':
        return extract_text_from_docx(file_path)
    elif file_extension == '.txt':
        return extract_text_from_txt(file_path)
    else:
        return None

def extract_contact_info(text):
    """Extract contact information from text"""
    contact_info = {}
    
    # Email extraction
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    if emails:
        contact_info['email'] = emails[0]
    
    # Phone number extraction (various formats)
    phone_patterns = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # 123-456-7890 or 123.456.7890
        r'\(\d{3}\)\s*\d{3}[-.]?\d{4}',    # (123) 456-7890
        r'\+\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}'  # +1-123-456-7890
    ]
    
    for pattern in phone_patterns:
        phones = re.findall(pattern, text)
        if phones:
            contact_info['phone'] = phones[0]
            break
    
    # LinkedIn profile
    linkedin_pattern = r'linkedin\.com/in/[\w-]+'
    linkedin = re.findall(linkedin_pattern, text.lower())
    if linkedin:
        contact_info['linkedin'] = linkedin[0]
    
    # GitHub profile
    github_pattern = r'github\.com/[\w-]+'
    github = re.findall(github_pattern, text.lower())
    if github:
        contact_info['github'] = github[0]
    
    return contact_info

def extract_skills_from_text(text):
    """Extract technical skills from text"""
    text_lower = text.lower()
    found_skills = []
    
    for skill in ALL_SKILLS:
        # Use word boundaries to avoid partial matches
        pattern = r'\b' + re.escape(skill.lower()) + r'\b'
        if re.search(pattern, text_lower):
            found_skills.append(skill)
    
    # Remove duplicates and return
    return list(set(found_skills))

def extract_experience(text):
    """Extract work experience information"""
    experience = []
    
    # Look for common experience patterns
    experience_patterns = [
        r'(\d{4})\s*[-–]\s*(\d{4}|\w+)\s*[:\-]?\s*([^\n]+)',  # 2020-2023: Job Title
        r'(\w+\s+\d{4})\s*[-–]\s*(\w+\s+\d{4}|\w+)\s*[:\-]?\s*([^\n]+)',  # Jan 2020 - Dec 2023: Job Title
    ]
    
    for pattern in experience_patterns:
        matches = re.findall(pattern, text, re.MULTILINE)
        for match in matches:
            if len(match) >= 3:
                experience.append({
                    'start_date': match[0],
                    'end_date': match[1],
                    'description': match[2].strip()
                })
    
    return experience[:5]  # Return top 5 experiences

def extract_education(text):
    """Extract education information"""
    education = []
    
    # Common degree patterns
    degree_patterns = [
        r'(bachelor|master|phd|doctorate|diploma|certificate)[\s\w]*in\s+([^\n,]+)',
        r'(b\.?s\.?|m\.?s\.?|b\.?a\.?|m\.?a\.?|ph\.?d\.?)\s+in\s+([^\n,]+)',
        r'(undergraduate|graduate)\s+in\s+([^\n,]+)'
    ]
    
    for pattern in degree_patterns:
        matches = re.findall(pattern, text.lower(), re.MULTILINE)
        for match in matches:
            education.append({
                'degree': match[0].title(),
                'field': match[1].strip().title()
            })
    
    return education[:3]  # Return top 3 education entries

def calculate_resume_score(skills, experience, education, contact_info):
    """Calculate overall resume score"""
    score = 0
    
    # Skills score (40% of total)
    skills_score = min(len(skills) * 2, 40)
    score += skills_score
    
    # Experience score (30% of total)
    experience_score = min(len(experience) * 6, 30)
    score += experience_score
    
    # Education score (20% of total)
    education_score = min(len(education) * 7, 20)
    score += education_score
    
    # Contact info score (10% of total)
    contact_score = len(contact_info) * 2.5
    score += min(contact_score, 10)
    
    return min(score, 100)  # Cap at 100

def calculate_match_score(resume_skills, job_skills):
    """Calculate match score between resume and job requirements"""
    if not job_skills:
        return 0
    
    resume_skills_lower = [skill.lower() for skill in resume_skills]
    job_skills_lower = [skill.lower() for skill in job_skills]
    
    matched_skills = set(resume_skills_lower) & set(job_skills_lower)
    match_percentage = (len(matched_skills) / len(job_skills_lower)) * 100
    
    return round(match_percentage, 2)

def process_resume(file_path, original_filename, user_id=None):
    """Main function to process uploaded resume"""
    try:
        # Extract text from file
        text = extract_text_from_file(file_path)
        if not text:
            return {'success': False, 'error': 'Could not extract text from file'}
        
        # Extract information
        contact_info = extract_contact_info(text)
        skills = extract_skills_from_text(text)
        experience = extract_experience(text)
        education = extract_education(text)
        
        # Calculate overall score
        overall_score = calculate_resume_score(skills, experience, education, contact_info)
        
        # Save to database
        conn = sqlite3.connect('resume_analyzer.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO resumes 
            (user_id, filename, original_filename, extracted_text, skills, experience, education, contact_info, overall_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            os.path.basename(file_path),
            original_filename,
            text,
            json.dumps(skills),
            json.dumps(experience),
            json.dumps(education),
            json.dumps(contact_info),
            overall_score
        ))
        
        resume_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            'success': True,
            'resume_id': resume_id,
            'skills': skills,
            'experience': experience,
            'education': education,
            'contact_info': contact_info,
            'overall_score': overall_score
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}