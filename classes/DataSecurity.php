<?php

class DataSecurity {

    // 1. Sanitize input to prevent XSS (Cross-site Scripting)
    public static function sanitizeInput(string $data): string {
        return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
    }

    // 2. Hash password securely using bcrypt
    public static function hashPassword(string $password): string {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    // 3. Verify password hash
    public static function verifyPassword(string $password, string $hashedPassword): bool {
        return password_verify($password, $hashedPassword);
    }

    // 4. Generate a secure token for CSRF protection
    public static function generateToken(): string {
        return bin2hex(random_bytes(32));
    }

    // 5. Validate token (for CSRF attacks)
    public static function validateToken(string $token, string $sessionToken): bool {
        return hash_equals($sessionToken, $token);
    }

    // 6. Sanitize email input to prevent injection attacks
    public static function sanitizeEmail(string $email): string {
        return filter_var($email, FILTER_SANITIZE_EMAIL);
    }

    // 7. Prevent SQL Injection by escaping special characters
    public static function escapeSqlString(string $data): string {
        return addslashes($data);
    }

    // 8. Securely encrypt data
    public static function encryptData(string $data, string $key): string {
        $cipher = "aes-128-ctr";
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));
        return base64_encode($iv . openssl_encrypt($data, $cipher, $key, 0, $iv));
    }

    // 9. Decrypt data
    public static function decryptData(string $encryptedData, string $key): string {
        $cipher = "aes-128-ctr";
        $data = base64_decode($encryptedData);
        $ivLength = openssl_cipher_iv_length($cipher);
        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);
        return openssl_decrypt($encrypted, $cipher, $key, 0, $iv);
    }
}
