from models import encrypt_data, decrypt_data

def test_encryption_decryption():
    secret = 'Sensitive diagnosis info'
    encrypted = encrypt_data(secret)
    assert encrypted != secret
    decrypted = decrypt_data(encrypted)
    assert decrypted == secret
