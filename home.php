<?php
session_start();

// Add Content Security Policy (CSP) Header
header("Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self';");

// Enforce HTTPS
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

// Redirect to login if not authenticated
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

// Ensure CSRF token exists (generated in login.php)
if (empty($_SESSION['csrf_token'])) {
    die('CSRF token not found. Please log in again.');
}

// File upload directory
$uploadDir = __DIR__ . '/uploads/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0600);
}

$message = '';

// Secure delete function
function secureDelete($filePath) {
    if (file_exists($filePath)) {
        $size = filesize($filePath);
        $fp = fopen($filePath, 'wb');
        fwrite($fp, random_bytes($size));
        fclose($fp);
        unlink($filePath);
    }
}

// Derive encryption key from password
function deriveKey($password) {
    return hash('sha256', $password, true); // Generate a 256-bit key
}

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        die('Invalid CSRF token.');
    }

    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
    
        // Define allowed MIME types
        $allowedMimeTypes = [
            'text/plain',
            'application/pdf',
            'image/png',
            'image/jpeg',
            'image/gif',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
    
        // Check file MIME type
        $fileMimeType = mime_content_type($file['tmp_name']);
        if (!in_array($fileMimeType, $allowedMimeTypes)) {
            $message = 'Invalid file type. Allowed types: text, PDF, images, and Word documents.';
        } else {
            // Sanitize file name
            $filename = preg_replace('/[^a-zA-Z0-9_\.-]/', '_', basename($file['name']));
            $targetPath = $uploadDir . $filename;
    
            // Move the uploaded file to the target directory
            if (move_uploaded_file($file['tmp_name'], $targetPath)) {
                $message = 'File uploaded successfully.';
            } else {
                $message = 'File upload failed.';
            }
        }
    } elseif (isset($_POST['operation']) && isset($_POST['file'])) {
        $selectedFile = $uploadDir . $_POST['file'];

        if (!file_exists($selectedFile)) {
            $message = 'Selected file not found.';
        } elseif ($_POST['operation'] === 'delete') {
            // Securely delete the file
            secureDelete($selectedFile);
            $message = 'File securely deleted.';
        } elseif (isset($_POST['password'])) {
            $password = $_POST['password'];
            if (empty($password)) {
                $message = 'Password is required for encryption or decryption.';
            } else {
                $data = file_get_contents($selectedFile);
                $key = deriveKey($password); // Derive encryption key

                if ($_POST['operation'] === 'encrypt') {
                    $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
                    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);

                    if ($encrypted === false) {
                        $message = 'Encryption failed.';
                    } else {
                        $outputName = $_POST['file'] . '.enc'; // Add .enc to original filename
                        $outputPath = $uploadDir . $outputName;
                        $outputData = base64_encode($iv . '::' . $_POST['file'] . '::' . $encrypted);

                        if (file_put_contents($outputPath, $outputData) === false) {
                            $message = 'Failed to save the encrypted file.';
                        } else {
                            $message = "File encrypted successfully as $outputName.";
                        }
                    }
                } elseif ($_POST['operation'] === 'decrypt') {
                    $decoded = base64_decode($data);
                    if (!$decoded || strpos($decoded, '::') === false) {
                        $message = 'Decryption failed. Invalid file format.';
                    } else {
                        [$iv, $storedName, $encryptedData] = explode('::', $decoded, 3);
                        $decrypted = openssl_decrypt($encryptedData, 'aes-256-cbc', $key, 0, $iv);

                        if ($decrypted === false) {
                            $message = 'Decryption failed. Invalid password or corrupted file.';
                        } else {
                            $outputName = $storedName ?: $_POST['file'] . '.dec'; // Restore or default to .dec
                            $outputPath = $uploadDir . $outputName;

                            if (file_put_contents($outputPath, $decrypted) === false) {
                                $message = 'Failed to save the decrypted file.';
                            } else {
                                $message = "File decrypted successfully as $outputName.";
                            }
                        }
                    }
                }
            }
        }
    } elseif (isset($_POST['download']) && isset($_POST['file'])) {
        // Handle file download
        $selectedFile = $uploadDir . $_POST['file'];
        if (file_exists($selectedFile)) {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($selectedFile) . '"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($selectedFile));
            readfile($selectedFile);
            exit();
        } else {
            $message = 'File not found for download.';
        }
    }
}

// Logout button handling
if (isset($_POST['logout'])) {
    session_unset();
    session_destroy();
    header("Location: login.php");
    exit();
}

// Fetch files in the uploads directory
$files = array_diff(scandir($uploadDir), ['.', '..']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Management</title>
    <link rel="stylesheet" href="styles/home.css">
</head>
<body>
    <div class="home-container">
        <h2>File Management</h2>
        <p><?= htmlspecialchars($message) ?></p>

        <!-- File Upload Form -->
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <label for="file">Upload File:</label>
            <input type="file" name="file" id="file" required>
            <button type="submit">Upload</button>
        </form>

        <!-- List of Files -->
        <h3>Available Files</h3>
        <?php if (!empty($files)): ?>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <label for="file">Select a File:</label>
                <select name="file" id="file" required>
                    <?php foreach ($files as $file): ?>
                        <option value="<?= htmlspecialchars($file) ?>"><?= htmlspecialchars($file) ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="password" name="password" placeholder="Enter password (required for Encrypt/Decrypt)">
                <button type="submit" name="operation" value="encrypt">Encrypt</button>
                <button type="submit" name="operation" value="decrypt">Decrypt</button>
                <button type="submit" name="operation" value="delete">Delete</button>
                <button type="submit" name="download">Download</button>
            </form>
        <?php else: ?>
            <p>No files available.</p>
        <?php endif; ?>

        <!-- Logout Button -->
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <button type="submit" name="logout">Logout</button>
        </form>
    </div>
</body>
</html>
