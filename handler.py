import logging
import logg
import encryption
import base64
import requests


class ChatHandler:
    """Class for processing the chat"""

    @staticmethod
    def process_message(user: str, message: str) -> dict:
        """
        Function to process the chat message before sending to the server
        :param user:
        :param message:
        :return:
        """
        encrypted_message = encryption.EncryptionHelper.aes_encrypt(message.encode())

        hmac_signature = encryption.EncryptionHelper.generate_hmac(encrypted_message)
        message = {'user': user,
                   'message': base64.b64encode(encrypted_message).decode(),
                   'hmac_signature': hmac_signature}
        return message
