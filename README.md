# password-generator
This Python script provides a secure password generator that incorporates cryptographic hashing for enhanced security. It produces strong and random passwords, assesses their strength based on common security standards, and offers the hashed version of the generated password for secure storage and verification.

## Features:

+ **Strong Password Generation:** Generates strong passwords with customizable length and character sets.
+ **Password Strength Assessment:** Assesses password strength based on security standards and best practices.
+ **Cryptographic Hashing:** Securely hashes generated passwords using SHA-256.
+ **Attack Simulation:** Simulates common password attack scenarios like dictionary and brute-force attacks for testing.

## Motivation:

This project was made for myself as an introduction to cybersecurity, in the hopes to demonstrate security knowledge and experience. More specifically:

+ **Knowledge of Security Standards and Frameworks:** The password strength assessment considers security standards such as ISO27001 and NIST.
+ **Penetration Testing Techniques:** The script includes options to simulate common password attack scenarios to show knowledge of penetration testing techniques used to assess password security.
+ **Understanding of Security Concepts:** Password strength assessment checks for a mix of character types, avoidance of common patterns, and detection of sequential characters to show understanding of security principles.
+ **Experience with Ethical Hacking/Penetration Testing:** Simulation of password attack scenarios reflects experience with ethical hacking and penetration testing, where testers often attempt to crack passwords using known patterns or weak passwords.


## How It Works:

+ **Brute-Force Simulation:** It simulates brute-force attacks by randomly generating passwords. When the simulate_attack parameter is set to "brute_force", a random password is generated, mimicking the process of trying all possible combinations.
+ **Chance for Attack Simulation:** it introduces a 33% chance of simulating an attack. If the simulate_attack parameter is not specified or if a random value falls below this threshold, the script generates a strong password without simulating an attack.
