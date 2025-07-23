import bcrypt
import base64

def pad_base64(b64_string):
    return b64_string + '=' * (-len(b64_string) % 4)


def generate_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password_hash(hashed_password: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

class Applicant(BaseModel):
    id: str
    name: str
    email: str
    resumeScore: Optional[int] = None
    oaScore: Optional[int] = None
    resumeFile: Optional[str] = None
    resumeFileName: Optional[str] = None
    college: str
    degree: str
    experience: int

def generate_dummy_candidates(job_id: str) -> List[Applicant]:
    """Generate realistic dummy candidate data"""
    
    # Sample names
    first_names = [
        "Arjun", "Priya", "Rahul", "Sneha", "Vikram", "Ananya", "Rohan", "Kavya",
        "Aaditya", "Ishita", "Siddharth", "Meera", "Karthik", "Riya", "Abhishek",
        "Pooja", "Nikhil", "Shreya", "Varun", "Divya", "Akash", "Nandini",
        "Raj", "Sakshi", "Arun", "Kritika", "Shubham", "Tanvi", "Harsh", "Ritika"
    ]
    
    last_names = [
        "Sharma", "Patel", "Singh", "Kumar", "Gupta", "Agarwal", "Joshi", "Shah",
        "Reddy", "Iyer", "Nair", "Malhotra", "Chopra", "Bansal", "Mehta",
        "Verma", "Sinha", "Tiwari", "Mishra", "Pandey", "Saxena", "Arora"
    ]
    
    # Sample colleges
    colleges = [
        "IIT Delhi", "IIT Bombay", "IIT Madras", "IIT Kanpur", "IIT Kharagpur",
        "NIT Trichy", "NIT Warangal", "BITS Pilani", "VIT Vellore", "SRM Chennai",
        "Delhi University", "Mumbai University", "Anna University", "IIIT Hyderabad",
        "MIT Manipal", "PES University", "RV College of Engineering", "BMS College",
        "Jadavpur University", "Pune University", "NITK Surathkal", "IIIT Bangalore"
    ]
    
    # Sample degrees
    degrees = [
        "B.Tech Computer Science", "B.Tech Information Technology", "B.Tech Electronics",
        "B.E Computer Science", "B.E Information Science", "MCA", "M.Tech CSE",
        "B.Tech Software Engineering", "B.Tech Data Science", "BCA", "M.Sc Computer Science",
        "B.Tech Artificial Intelligence", "B.Tech Cybersecurity"
    ]
    
    # Generate 15-25 random candidates
    num_candidates = random.randint(15, 25)
    candidates = []
    
    for i in range(num_candidates):
        first_name = random.choice(first_names)
        last_name = random.choice(last_names)
        name = f"{first_name} {last_name}"
        email = f"{first_name.lower()}.{last_name.lower()}@{random.choice(['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'])}"
        
        # Random resume score (70% chance of having a score)
        resume_score = random.randint(45, 95) if random.random() < 0.7 else None
        
        # Random OA score (60% chance of having attended)
        oa_score = random.randint(30, 100) if random.random() < 0.6 else None
        
        # Resume file (85% chance of having uploaded)
        has_resume = random.random() < 0.85
        resume_file = f"https://example.com/resumes/{uuid.uuid4()}.pdf" if has_resume else None
        resume_file_name = f"{first_name}_{last_name}_Resume.pdf" if has_resume else None
        
        candidate = Applicant(
            id=str(uuid.uuid4()),
            name=name,
            email=email,
            resumeScore=resume_score,
            oaScore=oa_score,
            resumeFile=resume_file,
            resumeFileName=resume_file_name,
            college=random.choice(colleges),
            degree=random.choice(degrees),
            experience=random.randint(0, 8)
        )
        
        candidates.append(candidate)
    
    return candidates
