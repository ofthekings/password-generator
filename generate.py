import random
import string
import re
import hashlib


def generate_password(
    length=12,
    include_uppercase=True,
    include_digits=True,
    include_special=True,
    simulate_attack=None,
):
    """
    Generates a strong and secure password using cryptographic hashing.

    Parameters:
    - length: Length of the password (default: 12)
    - include_uppercase: Include uppercase letters (default: True)
    - include_digits: Include digits (default: True)
    - include_special: Include special characters (default: True)
    - simulate_attack: Type of password attack to simulate (default: None)

    Returns:
    - A tuple containing the generated password and its hashed version.
    """
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_special:
        characters += string.punctuation

    if (
        simulate_attack is None or random.random() < 0.33
    ):  # 33% chance of not simulating an attack
        password = "".join(random.choice(characters) for _ in range(length))
    elif simulate_attack == "dictionary":
        # Simulates dictionary attack by generating a password from a common dictionary
        common_passwords = [
            "password",
            "123456",
            "qwerty",
            "abc123",
            "letmein",
            "admin",
            "love",
            "password1",
        ]
        password = random.choice(common_passwords)
    else:
        # Simulates brute-force attack by generating a random password
        password = "".join(random.choice(characters) for _ in range(length))

    # Uses cryptographic hashing to securely store the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return password, hashed_password


def check_password_strength(password):
    """
    Checks the strength of a password based on security standards and best practices.

    Parameters:
    - password: The password to be checked.

    Returns:
    - A message indicating the strength of the password.
    """
    # Checks password length
    if len(password) < 12:
        return (
            "Weak password: Too short. Passwords should be at least 12 characters long."
        )

    # Checks for a mix of character types
    if not (
        any(char.isupper() for char in password)
        and any(char.islower() for char in password)
        and any(char.isdigit() for char in password)
        and any(char in string.punctuation for char in password)
    ):
        return "Weak password: Passwords should contain a mix of uppercase letters, lowercase letters, digits, and special characters."

    # Checks for common patterns
    common_patterns = [
        "password",
        "123456",
        "qwerty",
        "abc123",
        "letmein",
        "admin",
        "love",
        "password1",
    ]
    if password.lower() in common_patterns:
        return "Weak password: Commonly used password pattern detected."

    # Checks for sequential characters (e.g., "abcdef", "123456")
    if re.search(
        r"(?:abcdefghijklmnopqrstuvwxyz)|(?:0123456789)|(?:zyxwvutsrqponmlkjihgfedcba)|(?:9876543210)",
        password.lower(),
    ):
        return "Weak password: Sequential characters detected."

    return "Strong password."


if __name__ == "__main__":
    generated_password, hashed_password = generate_password(
        simulate_attack=random.choice([None, "dictionary", "brute_force"])
    )  # Selects randomly whether to simulate an attack
    print("Generated Password:", generated_password)
    print("Password Strength:", check_password_strength(generated_password))
    print("Hashed Password:", hashed_password)
