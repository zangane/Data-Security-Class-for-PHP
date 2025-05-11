# Data Security Class for PHP

This is a simple yet powerful PHP class for securing data. It includes various utility functions for sanitizing inputs, hashing passwords, preventing SQL injection, encrypting/decrypting data, and more. This class is designed to enhance the security of your PHP applications with minimal effort.

## Features

- **Sanitize Input**: Protect against XSS attacks by sanitizing input data.
- **Hash Passwords**: Securely hash user passwords using bcrypt.
- **Verify Password**: Easily verify hashed passwords.
- **CSRF Protection**: Generate and validate CSRF tokens.
- **Email Sanitization**: Prevent email injection attacks.
- **SQL Injection Prevention**: Escape SQL strings to prevent SQL injection.
- **Data Encryption**: Securely encrypt and decrypt sensitive data.

## Installation

1. Download or clone this repository:

```bash
git clone https://github.com/yourusername/data-security-php.git
```

2. Include the DataSecurity.php class in your project:

**require_once 'path/to/DataSecurity.php';**

3. Use the class methods for securing your data.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

This project was developed by Mohamad Zangane.
