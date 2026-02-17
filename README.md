# 🕵️ Cipher Sleuth

**Cipher Sleuth** is a modular, high-performance forensic engine and cryptographic solver designed for **PicoCTFs**. It automatically identifies, analyzes, and cracks various encoding schemes, hashes, and classical ciphers.

Designed as a single-binary CLI tool, it features recursive analysis, local solvers, and potential online fallbacks for challenging artifacts.

## 🚀 Installation

### Option 1: Install via Go (Recommended)
```bash
# Install directly from GitHub
go install github.com/byteoverride/cipher-sleuth@latest
```

### Option 2: Build from Source
```bash
# Clone the repository
git clone https://github.com/byteoverride/cipher-sleuth
cd cipher-sleuth

# Build the binary
go build -o cipher-sleuth
```

## 📖 Usage

```bash
cipher-sleuth [flags]
```

### Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-t <string>` | Direct text input to analyze. | `./cipher-sleuth -t "SGVsbG8="` |
| `-f <file>` | Path to a file to analyze. | `./cipher-sleuth -f flag.txt` |
| `--online` | Enable active network lookups (FactorDB, Hash APIs). | `./cipher-sleuth --online -t "2123..."` |

*Note: You can also pipe input via stdin:*
```bash
echo "rot13_text" | ./cipher-sleuth
```

## 🛠️ Features & Solvers

### 1. 🔍 Identification Engine (`config.go`)
*   **File Signatures**: Auto-detects magic bytes for PNG, JPG, ZIP, 7z, TAR, ELF, LUKS, PGP.
*   **Hash Identification**: Regex matching for MD5, SHA1, SHA256, SHA512, NTLM, Bcrypt, Argon2.
*   **Encodings**: Detects Base64, Base32, Base58, Hex, and URL encoding patterns.

### 2. 📊 Statistical Analysis (`stats.go`)
*   **Shannon Entropy**: Calculates data entropy (0-8) to detect encryption/compression.
*   **Index of Coincidence (IoC)**: Measures text 'roughness' to distinguish English text (~1.73) from random/encrypted data.

### 3. 🔓 Local Solvers (`solver.go`)
*   **Auto-Decoding**: recursivley decodes Base64, Hex, URL, Base32.
*   **Classical Ciphers**:
    *   **Rot13**: Auto-solves.
    *   **Caesar Cipher**: Brute-forces all 25 shifts checking for flag formats (`picoCTF{`).

### 4. 🔑 RSA Breaker (`solver_rsa.go`)
*   **Input Parsing**: Extracts `N`, `e`, `c` from raw text input (Decimal or Hex).
*   **Small Exponent Attack**: Automatically computes $m = \sqrt[e]{c}$ if $e$ is small and $m^e < N$.
*   **FactorDB Integration** (`--online`): Queries FactorDB to find factors $p, q$ for weak keys and derives the private key.

### 5. 🎭 Poly-Alphabetical Solver (`solver_poly.go`)
*   **XOR Buster**: Brute-forces Single-Byte XOR (0-255), scoring results via English frequency analysis.
*   **Vigenère Cracker**: Performs a Dictionary Attack using common CTF keys (e.g., "FLAG", "PICO", "ADMIN").

### 6. 🌐 Online Fallback (`solver_online.go`)
*   **Active Lookup** (`--online`): Queries reliable APIs (e.g., nitrxgen) to reverse simple hashes like MD5.
*   **Magic Links**: Always generates passive links to **CyberChef** (Magic recipe) and **dCode** for manual investigation.

## ⚡ Examples

### Solving a Rot13 Flag
<img width="1173" height="353" alt="image" src="https://github.com/user-attachments/assets/e3b8725c-0356-4d90-a3cf-9e8478ffebda" />


### Solving an RSA Challenge
<img width="1789" height="495" alt="image" src="https://github.com/user-attachments/assets/d73d546f-5c9e-4054-a56a-578f2c0e8395" />


### Solving XOR with Online Hash Lookup
```bash
./cipher-sleuth --online -f encrypted.bin
# Output: 
#   XOR Key: 0x55 -> "21232f297a57a5a743894a0e4a801fc3"
#   Active Lookup: Success! -> admin
```

