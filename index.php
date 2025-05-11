<?php
require_once __DIR__ . "/classes/DataSecurity.php";

// Test sanitize input
$userInput = "<script>alert('XSS Attack!');</script>";
echo "Sanitized Input: " . DataSecurity::sanitizeInput($userInput) . "<br><br>";

// Test password hashing and verification
$password = "securepassword123";
$hashedPassword = DataSecurity::hashPassword($password);
echo "Hashed Password: " . $hashedPassword . "<br>";

if (DataSecurity::verifyPassword($password, $hashedPassword)) {
    echo "Password is valid!<br><br>";
} else {
    echo "Password is invalid!<br><br>";
}

// Test CSRF token generation and validation
$token = DataSecurity::generateToken();
echo "Generated Token: " . $token . "<br>";
session_start();
$_SESSION['csrf_token'] = $token;
if (DataSecurity::validateToken($token, $_SESSION['csrf_token'])) {
    echo "Token validated successfully!<br><br>";
} else {
    echo "Invalid token!<br><br>";
}

// Test email sanitization
$email = "user@example<script>.com";
echo "Sanitized Email: " . DataSecurity::sanitizeEmail($email) . "<br><br>";

// Test SQL string escaping
$unsafeInput = "SELECT * FROM users WHERE username = 'admin'; DROP TABLE users;";
echo "Escaped SQL: " . DataSecurity::escapeSqlString($unsafeInput) . "<br><br>";

// Test encryption and decryption
$key = "encryptionkey123";
$originalData = "Sensitive Data";
$encryptedData = DataSecurity::encryptData($originalData, $key);
echo "Encrypted Data: " . $encryptedData . "<br>";
$decryptedData = DataSecurity::decryptData($encryptedData, $key);
echo "Decrypted Data: " . $decryptedData . "<br>";
?>
