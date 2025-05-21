from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import io

app = Flask(__name__)
app.secret_key = 'replace_with_a_secure_random_key'  # Đổi thành giá trị bí mật thực tế

# (HTML_TEMPLATE giữ nguyên như bạn đã có)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AES File Encryptor / Decryptor</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap');
  * {
    box-sizing: border-box;
  }
  body {
    margin: 0;
    background: #121217;
    color: #eee;
    font-family: 'Poppins', sans-serif;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 1rem;
  }
  .container {
    background: #1e1e2f;
    border-radius: 12px;
    box-shadow: 0 0 20px rgba(102, 51, 255, 0.6);
    width: 100%;
    max-width: 480px;
    padding: 2rem;
  }
  h1 {
    text-align: center;
    margin-bottom: 1rem;
    font-weight: 600;
    color: #8c82fc;
  }
  label {
    display: block;
    margin-bottom: 0.3rem;
    font-weight: 600;
    color: #b9aaff;
  }
  input[type="file"] {
    margin-bottom: 1rem;
    color: #ccc;
  }
  input[type="password"],
  input[type="text"] {
    width: 100%;
    padding: 0.6rem 1rem;
    border-radius: 6px;
    border: none;
    margin-bottom: 1rem;
    font-size: 1rem;
    background: #2d2d44;
    color: #eee;
    outline-offset: 2px;
    outline-color: #6e5eff;
  }
  .radio-group {
    margin-bottom: 1rem;
    display: flex;
    justify-content: center;
    gap: 1.5rem;
  }
  .radio-group label {
    font-weight: 500;
    color: #b9aaff;
    cursor: pointer;
  }
  button {
    width: 100%;
    padding: 0.8rem;
    font-size: 1.1rem;
    border: none;
    border-radius: 8px;
    background: #6e5eff;
    color: white;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.3s ease;
    user-select: none;
  }
  button:hover {
    background: #5749cc;
  }
  #message {
    margin-top: 1rem;
    text-align: center;
    font-weight: 600;
    min-height: 1.5rem;
  }
  #message.error {
    color: #ff5555;
  }
  #message.success {
    color: #8cfc82;
  }
  footer {
    margin-top: 1.5rem;
    text-align: center;
    font-size: 0.85rem;
    color: #6666cc;
  }
</style>
</head>
<body>
  <main class="container" role="main" aria-label="AES File Encryptor/Decryptor">
    <h1>AES File Encryptor / Decryptor</h1>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div id="message" role="alert" aria-live="assertive">
        {% for category, msg in messages %}
          <p class="{{ category }}">{{ msg }}</p>
        {% endfor %}
        </div>
      {% else %}
        <div id="message"></div>
      {% endif %}
    {% endwith %}

    <form method="POST" action="{{ url_for('process') }}" enctype="multipart/form-data" novalidate>
      <label for="fileInput">Choose file</label>
      <input type="file" id="fileInput" name="file" required aria-required="true" />

      <label for="passwordInput">Password (AES key)</label>
      <input type="password" id="passwordInput" name="password" placeholder="Enter password" required aria-required="true" />

      <div class="radio-group" role="radiogroup" aria-label="Choose action">
        <label><input type="radio" name="mode" value="encrypt" checked /> Encrypt</label>
        <label><input type="radio" name="mode" value="decrypt" /> Decrypt</label>
      </div>

      <button type="submit">Process File</button>
    </form>
  </main>
</body>
</html>
"""
def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + cipher.nonce + tag + ciphertext

def decrypt_bytes(data: bytes, password: str) -> bytes:
    if len(data) < 48:
        raise ValueError("Invalid data or corrupted file")
    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    ciphertext = data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/process', methods=['POST'])
def process():
    uploaded_file = request.files.get('file')
    password = request.form.get('password')
    mode = request.form.get('mode')

    if not uploaded_file or uploaded_file.filename == '':
        flash('Please select a file to upload.', 'error')
        return redirect(url_for('index'))

    if not password:
        flash('Please enter a password.', 'error')
        return redirect(url_for('index'))

    if mode not in ('encrypt', 'decrypt'):
        flash('Invalid mode selected.', 'error')
        return redirect(url_for('index'))

    try:
        file_data = uploaded_file.read()
        if mode == 'encrypt':
            processed_data = encrypt_bytes(file_data, password)
            output_filename = uploaded_file.filename + '.aes'
        else:
            processed_data = decrypt_bytes(file_data, password)
            if uploaded_file.filename.endswith('.aes'):
                output_filename = uploaded_file.filename[:-4]
            else:
                output_filename = uploaded_file.filename + '.decrypted'

        return send_file(
            io.BytesIO(processed_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=output_filename
        )
    except Exception as e:
        flash(f'Error during {mode}: {str(e)}', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

