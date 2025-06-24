<?php
session_start();
$page = $_GET['page'] ?? 'login';

// Koneksi ke database
$koneksi = new mysqli("localhost", "faizmysql", "030303", "web_auth");
if ($koneksi->connect_error) {
  die("Koneksi gagal: " . $koneksi->connect_error);
}

// Proses Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];

  $stmt = $koneksi->prepare("SELECT * FROM users WHERE username = ?");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $result = $stmt->get_result();
  $user = $result->fetch_assoc();

  if ($user && password_verify($password, $user['password'])) {
    $_SESSION['username'] = $user['username'];
    $_SESSION['fullname'] = $user['fullname'];
    header("Location: program_login.php?page=home");
    exit;
  } else {
    $error = "Username atau password salah!";
  }
}

// Proses Register
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
  $fullname = $_POST['fullname'];
  $username = $_POST['username'];
  $email = $_POST['email'];
  $passwordHash = password_hash($_POST['password'], PASSWORD_DEFAULT);

  // Cek apakah username atau email sudah digunakan
  $cek = $koneksi->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
  $cek->bind_param("ss", $username, $email);
  $cek->execute();
  $cekResult = $cek->get_result();

  if ($cekResult->num_rows > 0) {
    $error = "Username atau email sudah digunakan!";
    $page = 'register';
  } else {
    $stmt = $koneksi->prepare("INSERT INTO users (fullname, username, email, password) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $fullname, $username, $email, $passwordHash);
    $stmt->execute();

    $_SESSION['username'] = $username;
    $_SESSION['fullname'] = $fullname;
    header("Location: program_login.php?page=login");
    exit;
  }
}

// Logout
if ($page === 'logout') {
  session_destroy();
  header("Location: program_login.php");
  exit;
}
?>
<!DOCTYPE html>
<html lang="id">

<head>
  <meta charset="UTF-8">
  <title>Login App</title>
  <style>
    body {
      margin: 0;
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #74ebd5, #ACB6E5);
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }

    .container {
      background: #fff;
      padding: 30px;
      border-radius: 15px;
      box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
      width: 100%;
      max-width: 360px;
      text-align: center;
    }

    h2 {
      margin-bottom: 20px;
    }

    input,
    button {
      width: 100%;
      padding: 10px;
      margin: 8px 0;
      border-radius: 8px;
      border: 1px solid #ccc;
    }

    button {
      background-color: #0077b6;
      color: white;
      border: none;
      cursor: pointer;
    }

    button:hover {
      background-color: #023e8a;
    }

    .link {
      margin-top: 10px;
      display: block;
    }

    .error {
      color: red;
      margin-bottom: 10px;
    }
  </style>
</head>

<body>
  <div class="container">
    <?php if ($page === 'login'): ?>
      <h2>Login</h2>
      <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
      <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit" name="login">Masuk</button>
      </form>
      <a class="link" href="program_login.php?page=register">Belum punya akun? Daftar</a>

    <?php elseif ($page === 'register'): ?>
      <h2>Registrasi</h2>
      <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
      <form method="POST">
        <input type="text" name="fullname" placeholder="Nama Lengkap" required><br>
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="email" name="email" placeholder="Email" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit" name="register">Daftar</button>
      </form>
      <a class="link" href="program_login.php">Sudah punya akun? Login</a>

    <?php elseif ($page === 'home' && isset($_SESSION['username'])): ?>
      <h2>Selamat Datang, <?= htmlspecialchars($_SESSION['fullname']) ?>!</h2>
      <p>Login berhasil ✅</p>
      <a class="link" href="program_login.php?page=logout">Logout</a>

    <?php else: ?>
      <p>Silakan login terlebih dahulu.</p>
      <a class="link" href="program_login.php">Kembali ke Login</a>
    <?php endif; ?>
  </div>
</body>

</html>