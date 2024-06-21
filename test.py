import handler
import encryption
import logging
import logg
import requests
import base64

log = logg.setup_logger(name="TEST", level=logging.DEBUG)


def test_send_message():
    log.critical("===============TESTING SENDING MESSAGE PROCESS===============")
    response = handler.ChatHandler.process_message(user="Test", message="Hello")

    log.critical("[*] TESTING SENDING MESSAGE user = test, message = hello")
    log.critical(f"[*] RESPONSE OF TEST {response} MESSAGE\n")
    log.critical("===============TESTING SENDING CORRECT MESSAGE===============")
    correct_response = requests.post("http://127.0.0.1:8000/send_message", json=response).json()
    log.critical(f"[*] RESPONSE UNTAMPERED MESSAGE: {correct_response}\n")

    log.critical("===============TAMPERING MESSAGE===============")
    enc_message = {"user": "Test", "message": "THIS IS TAMPERED", "hmac_signature": f"{response.get('hmac_signature')}"}
    log.critical(f"[*] TAMPERED MESSAGE {enc_message}\n")
    log.critical("===============TESTING SENDING TAMPERED MESSAGE===============")
    wrong_response = requests.post("http://127.0.0.1:8000/send_message", json=enc_message).json()
    log.critical(f"[*] RESPONSE TAMPERED MESSAGE: {wrong_response}")


def test_decrypt_message():
    response = handler.ChatHandler.process_message(user="Test", message="Hello")
    log.critical(f"RESPONSE OF TEST {response}")
    if encryption.EncryptionHelper.verify_hmac(ciphertext=base64.b64decode(response['message']),
                                               received_hmac=response['hmac_signature']):
        decrypted_message = encryption.EncryptionHelper.aes_decrypt(base64.b64decode(response['message']))
        print(decrypted_message)
    else:
        print("MESSAGE IS TAMPERED")


if __name__ == "__main__":
    test_send_message()
    test_decrypt_message()