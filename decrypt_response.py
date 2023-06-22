from Crypto.Cipher import AES
import config
import base64


def decrypt(salt, ciphertext):
    ciphertext_bytes = base64.urlsafe_b64decode(ciphertext)
    initialization_vector_bytes = base64.urlsafe_b64decode(salt)
    key_bytes = base64.b64decode(config.KEY)
    tag_length = 16

    """Decrypts ciphertext encrypted with standard java.base.javax.crypto.Cipher transformation AES/GCM/NoPadding into plaintext.

    Assumes that authentication tag is appended to the ciphertext as documented in the link below.
    https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html

    Parameters:
      ciphertext_bytes (bytes): The ciphertext as binary data.
      initialization_vector_bytes (bytes): The initialization vector as binary data.
      key_bytes (bytes): The key as binary data.
      tag_length (int): The length of authentication tag. (default 16)
    Returns:
      plaintext (bytes): Binary data of the decrypted ciphertext.
    """
    # separate data from authentication tag
    data_bytes = ciphertext_bytes[:-tag_length]
    # separate authentication tag from data
    tag_bytes = ciphertext_bytes[-tag_length:]

    cipher = AES.new(key_bytes, AES.MODE_GCM, initialization_vector_bytes)
    plaintext_bytes = cipher.decrypt_and_verify(data_bytes, tag_bytes)

    return plaintext_bytes.decode("utf-8")
