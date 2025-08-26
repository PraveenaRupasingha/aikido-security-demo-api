# Aikido Security Demo API

⚠️ **WARNING: This application contains INTENTIONAL security vulnerabilities for testing purposes only. Never use in production!**

## Overview

This is a deliberately vulnerable Flask API designed to test Aikido Security's domain and API scanning capabilities. It contains multiple security vulnerabilities that security scanners should detect.

## 🚨 Vulnerabilities Included

- **SQL Injection** - Multiple endpoints with unsafe database queries
- **Command Injection** - System command execution without sanitization
- **Server-Side Template Injection (SSTI)** - Unsafe template rendering
- **Insecure Deserialization** - Unsafe pickle deserialization
- **Information Disclosure** - Exposed sensitive system information
- **Path Traversal** - Unsafe file operations
- **Security Misconfigurations** - Debug mode, permissive CORS

## 🚀 Quick Deploy

### Deploy to Render.com (Recommended)
1. Fork this repository
2. Go to [Render.com](https://render.com/)
3. Create new Web Service
4. Connect your GitHub repo
5. Use default Python settings
6. Deploy!

### Local Development
```bash
git clone https://github.com/yourusername/aikido-security-demo-api.git
cd aikido-security-demo-api
pip install -r requirements.txt
python app.py
```

## 📡 API Endpoints

| Endpoint | Method | Vulnerability | Test Payload |
|----------|--------|---------------|--------------|
| `/api/users` | GET | SQL Injection | `?username=admin' OR '1'='1` |
| `/api/login` | POST | SQL Injection | `{"username": "admin' OR '1'='1", "password": "test"}` |
| `/api/ping` | GET | Command Injection | `?host=google.com; whoami` |
| `/api/template` | GET | SSTI | `?name={{7*7}}` |
| `/api/debug` | GET | Info Disclosure | - |
| `/api/process` | POST | Deserialization | `{"data": "base64_pickle_data"}` |
| `/api/files` | GET | Path Traversal | `?file=../etc/passwd` |

## 🧪 Testing with Aikido Security

1. Deploy this app to get a public URL
2. Add the URL to Aikido Security domain scanning
3. Link to this GitHub repository
4. Run scans to detect vulnerabilities

## 📝 Sample Requests

### SQL Injection Test
```bash
curl "https://your-app.onrender.com/api/users?username=admin'%20OR%20'1'='1"
```

### Command Injection Test
```bash
curl "https://your-app.onrender.com/api/ping?host=google.com;%20ls"
```

### SSTI Test
```bash
curl "https://your-app.onrender.com/api/template?name={{7*7}}"
```

## 🔒 Security Notice

This application is created solely for security testing and educational purposes. It contains multiple intentional vulnerabilities:

- Do not deploy in production environments
- Do not use any code patterns from this repository in real applications
- Only use for authorized security testing

## 📚 Educational Use

Perfect for:
- Security scanner testing
- Penetration testing practice
- Security awareness training
- OWASP Top 10 demonstrations

## License

MIT License - Use responsibly for educational purposes only.
