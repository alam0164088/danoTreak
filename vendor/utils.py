import random
import string

def generate_aliffited_id():
    prefix = "ALF"
    
    random_part = ''.join(random.choices(string.digits, k=6))
    return f"{prefix}{random_part}"
