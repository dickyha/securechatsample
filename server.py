import logging
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import encryption
import base64
import logg
import datetime as dt
import config

log = logg.setup_logger(name="Secure-Server-Leviathan", level=logging.DEBUG)
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

"""
Message format.
{'user': user,
    'message': base64.b64encode(encrypted_message).decode(),
    'hmac_signature': hmac_signature}
"""


class Message(BaseModel):
    user: str
    message: str
    hmac_signature: str

message_pool: List[Message] = []

@app.post("/send_message")
async def send_message(message: Message):
    try:
        if encryption.EncryptionHelper.verify_hmac(ciphertext=base64.b64decode(message.message),
                                                   received_hmac=message.hmac_signature):
            log.debug(f"Message PASSED HMAC check {message}")
            message_pool.append(message)
            return {"status": 200, "data": "Message received"}
        else:
            log.debug(f"Message FAILED HMAC check {message}")
            return {"status": 500, "data": "Message seems to be tampered with"}
    except Exception as e:
        return {"status": 500, "data": "Message seems to be tampered with"}


@app.get("/get_messages")
async def get_messages():
    return {"status": 200, "data": message_pool}


if __name__ == "__main__":
    uvicorn.run(app, host=config.SERVER_ADDR, port=config.SERVER_PORT)
