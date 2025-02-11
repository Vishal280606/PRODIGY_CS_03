import re

def check_password_strength(password):
    length_criteria = len(password) >= 8
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special_char = bool(re.search(r'[\W_]', password))
    if length_criteria and has_uppercase and has_lowercase and has_digit and has_special_char:
        strength = "Strong"
        feedback = "Your password is strong!"
    elif length_criteria and (has_uppercase or has_lowercase) and has_digit:
        strength = "Medium"
        feedback = "Your password is medium strength. Consider adding special characters for added security."
    else:
        strength = "Weak"
        feedback = "Your password is weak. Make it at least 8 characters long with uppercase letters, digits, and special characters."

    return strength, feedback

def main():
    password = input("Enter your password: ")
    strength, feedback = check_password_strength(password)
    print(f"Password Strength: {strength}")
    print(feedback)

if __name__ == "__main__":
    main()
