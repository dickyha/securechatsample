from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import logging
import config
import logg

log = logg.setup_logger(name="Genbu-Encryption", level=logging.DEBUG)

class EncryptionHelper:
    """Class for encryption and decryption processes"""
    @staticmethod
    def aes_encrypt(plaintext: bytes) -> bytes:
        """
        function for AES encrypt the given plaintext
        :param plaintext:
        :return: ciphertext
        """
        cipher = AES.new(config.SECRET_KEY, AES.MODE_CBC) #create new cipher
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        log.debug(f"First Ciphertext: {ciphertext}")
        ciphertext = cipher.iv + ciphertext #this way we dont send the IV back, so I've opted to put the IV and ciphertext together
        log.debug(f"IV: {cipher.iv}")
        log.debug(f"IV + Ciphertext: {ciphertext}")

        return ciphertext

    @staticmethod
    def aes_decrypt(ciphertext: bytes) -> bytes:
        """
        function for AES Decrypting
        :param ciphertext:
        :return:
        """
        iv = ciphertext[:AES.block_size] #separating the IV
        log.debug(f"IV: {iv}")
        ciphertext = ciphertext[AES.block_size:]
        log.debug(f"Ciphertext: {ciphertext}")
        cipher = AES.new(config.SECRET_KEY, AES.MODE_CBC, iv=iv) #create new instance
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        log.debug(f"Decrypted: {decrypted}")
        return decrypted

    @staticmethod
    def generate_hmac(ciphertext: bytes) -> str:
        """
        function for generating hmac
        :param ciphertext:
        :return:
        """
        mac = hmac.new(config.SECRET_KEY, ciphertext, hashlib.sha256).hexdigest() #hexdigest so it can be send in a json
        log.debug(f" NEW GENERATED HMAC: {mac} for {ciphertext}")
        return mac

    @staticmethod
    def verify_hmac(ciphertext: bytes, received_hmac: str) -> bool:
        """
        function for verifying hmac
        :param ciphertext:
        :param received_hmac:
        :return:
        """
        calculated_hmac = EncryptionHelper.generate_hmac(ciphertext=ciphertext)
        log.debug(f"CALCULATED HMAC: {calculated_hmac}")
        log.debug(f"RECEIVED CIPHERTEXT: {ciphertext}")
        log.debug(f"RECEIVED HMAC: {received_hmac}")
        return hmac.compare_digest(calculated_hmac, received_hmac)

