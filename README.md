# SecurePHP

## Overview
**SecurePHP** is a PHP-based web application for secure file management. It provides functionalities for uploading, downloading, encrypting, decrypting, and securely deleting files. The application prioritizes security by implementing strong access controls, file sanitization, and encryption mechanisms.

---

## Features
- **User Authentication:** Secure login system with CSRF protection and hashed passwords.
- **File Upload and Download:** Allows users to upload and download files securely.
- **File Encryption and Decryption:** Encrypts and decrypts files using AES-256-CBC with password-derived keys.
- **Secure File Deletion:** Ensures sensitive files are securely overwritten and removed.
- **Content Security Policy (CSP):** Mitigates XSS attacks by enforcing strict CSP rules.
- **HTTPS Enforcement:** Redirects users to HTTPS for secure communication.
- **Filename Sanitization:** Protects against path traversal attacks.
- **Session Management:** Prevents session fixation attacks by regenerating session IDs after login.

---

## Requirements
- **Server Requirements:**
  - PHP 7.4 or higher
  - HTTPS-enabled web server (e.g., Apache, Nginx)
  - File upload permissions

- **Dependencies:**
  - OpenSSL for encryption/decryption
  - A PHP environment with `session`, `hash`, and `openssl` modules enabled

---

## Usage
### Setup
1. Place all files (`home.php`, `login.php`, `logout.php`, `config.php`) in the root directory of your PHP server.
2. Update the `config.php` file with your desired username and a hashed password (e.g., using `password_hash()` in PHP).
3. Ensure the `uploads` directory exists and has appropriate permissions (`chmod 700 uploads`).

### User Authentication
1. Navigate to `login.php`.
2. Enter the username and password configured in `config.php`. (Default Username: `user`, Default Password: `password`)
3. Upon successful login, you will be redirected to `home.php`.

### File Operations
1. **Upload a File:**
   - Use the file upload form to select and upload a file.
   - Only certain MIME types are allowed (e.g., text, images, PDFs, Word documents).
2. **Encrypt a File:**
   - Select a file from the available list.
   - Enter a password and click "Encrypt."
3. **Decrypt a File:**
   - Select an encrypted file.
   - Provide the correct password and click "Decrypt."
4. **Securely Delete a File:**
   - Select a file and click "Delete."
5. **Download a File:**
   - Select a file and click "Download."

### Logout
Click the "Logout" button to end your session securely.

---

## Security Features
- **CSRF Protection:** Validates tokens for all POST requests.
- **Hashed Passwords:** Ensures credentials are stored securely using PHP’s `password_hash()` function.
- **Strict CSP:** Allows only self-origin scripts and styles.
- **Sanitized File Inputs:** Prevents malicious file paths and filenames.
- **HTTPS Redirection:** Ensures secure communication.
- **Secure Deletion:** Overwrites files before deletion to prevent recovery.

---

## Examples
### Encrypting a File
1. Log in to the application.
2. Upload a file to the server.
3. Select the uploaded file, provide a password, and click "Encrypt."

### Decrypting a File
1. Select an encrypted file from the list.
2. Enter the password used during encryption.
3. Click "Decrypt" to restore the file.
