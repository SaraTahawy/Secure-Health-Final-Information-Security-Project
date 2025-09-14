# Security Testing Guide

## SQLMap Example
Test login for SQL injection:
```bash
sqlmap -u "http://127.0.0.1:5000/login" --data "email=test@user.com&password=test" --batch --risk=3 --level=5
```

## Nmap Example
Scan server ports:
```bash
nmap -sV 127.0.0.1
```

## XSS Test Script (Python)
```python
import requests
payload = '<script>alert(1)</script>'
res = requests.post('http://127.0.0.1:5000/comment', data={'comment': payload})
print('XSS test sent, check app response and browser.')
```

## Brute-force Test Script (Python)
```python
import requests
for i in range(10):
    res = requests.post('http://127.0.0.1:5000/login', data={'email': 'test@user.com', 'password': 'wrongpass'})
    print(f'Attempt {i+1}:', res.status_code)
```

## Encryption/Decryption Test
See `test_encryption.py` for a sample pytest.

---
Run all tests with:
```bash
pytest tests/
```
