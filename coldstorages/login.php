<?php
session_start(); // Start the session

// Database configuration
$host = 'localhost';
$dbname = 'coldstorages';
$username = 'root';
$password = '';

// Create a new PDO instance
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die('Connection failed: ' . $e->getMessage());
}

// Retrieve and sanitize form data
$email = trim($_POST['email']);
$password = trim($_POST['password']);

// Validate and sanitize inputs
if (empty($email) || empty($password)) {
    echo json_encode(['status' => 'error', 'message' => 'Both fields are required.']);
    exit;
}

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid email format.']);
    exit;
}

// Check if email exists
$sql = 'SELECT * FROM users WHERE email = :email';
$stmt = $pdo->prepare($sql);
$stmt->execute(['email' => $email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user) {
    // Verify the password
    if (password_verify($password, $user['password'])) {
        // Password is correct
        $_SESSION['user_id'] = $user['id']; // Store user ID in session
        $_SESSION['user_email'] = $user['email']; // Store user email in session

        // Insert login details into `login` table
        $sql = 'INSERT INTO login (user_id, email, password) VALUES (:user_id, :email, :password)';
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            'user_id' => $user['id'],
            'email' => $email,
            'password' => $password // Store plain password is not recommended; consider not storing it
        ]);

        // Output JSON response for successful login
        echo json_encode(['status' => 'success', 'message' => 'Login successful!']);
    } else {
        // Password is incorrect
        echo json_encode(['status' => 'error', 'message' => 'Invalid email or password.']);
    }
} else {
    // Email does not exist
    echo json_encode(['status' => 'error', 'message' => 'Invalid email or password.']);
}
?>
