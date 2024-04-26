import os.path
import re
import time
import logging

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import telebot
import threading

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Telegram bot API token
TOKEN = "TELEGRAM_KEY_API"
bot = telebot.TeleBot(TOKEN)

# Função para enviar mensagem periódica
def send_periodic_message(service):
    try:
        results = service.users().messages().list(userId="me", labelIds=["SENT"]).execute()
        messages = results.get("messages", [])

        if not messages:
            print("Nenhum e-mail encontrado.")
            return

        if len(messages) < 1:
            print("Precisa de pelo menos dois e-mails para comparar.")
            return

        latest_message_id = messages[0]['id']
        latest_subject = get_message_subject(service, "me", latest_message_id)
        email_sem_re = latest_subject.replace('Re: ', '')

        latest_name = get_message_name(service, "me", latest_message_id)
        texto_sem_arroba = re.sub(r' <.*?>', '', latest_name)
        texto_sem_aspas = texto_sem_arroba.replace('"', '')
        texto_sem_cargo = texto_sem_aspas.replace('[EJCM] ', '')

        second_latest_message_id = messages[1]['id']

        if latest_subject != send_periodic_message.previous_subject:
            send_periodic_message.previous_subject = latest_subject
            message = f"Respondi o E-mail de {texto_sem_cargo} sobre: {email_sem_re}"
            bot.send_message(chat_id="CHAT_USER_ID", text=message)
    except HttpError as error:
        logging.error(f"Ocorreu um erro: {error}")

# Manipulador para responder a mensagens recebidas
@bot.message_handler(func=lambda message: True)
def reply_to_message(message):
    try:
        bot.reply_to(message, 'Olá! Como posso ajudar?')
    except Exception as e:
        logging.error(f"Ocorreu um erro ao responder à mensagem: {e}")

def get_message_subject(service, user_id, message_id):
    """Obtém o assunto de uma mensagem de e-mail específica."""
    try:
        message = service.users().messages().get(userId=user_id, id=message_id).execute()
        payload = message['payload']
        headers = payload['headers']
        for header in headers:
            if header['name'] == 'Subject':
                return header['value']
    except HttpError as error:
        logging.error(f"Ocorreu um erro ao recuperar o assunto da mensagem: {error}")
    return None

def get_message_name(service, user_id, message_id):
    """Obtém o nome do destinatário de uma mensagem de e-mail específica."""
    try:
        message = service.users().messages().get(userId=user_id, id=message_id).execute()
        payload = message['payload']
        headers = payload['headers']
        for header in headers:
            if header['name'] == 'To':
                return header['value']
    except HttpError as error:
        logging.error(f"Ocorreu um erro ao recuperar o nome do destinatário da mensagem: {error}")
    return None

def main():
    """Função principal para buscar e-mails e enviar para o bot."""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        service = build("gmail", "v1", credentials=creds)

        # Definindo o assunto anterior como None na primeira execução
        send_periodic_message.previous_subject = None

        while True:
            send_periodic_message(service)
            time.sleep(5)
    except HttpError as error:
        logging.error(f"Ocorreu um erro: {error}")

if __name__ == "__main__":
    threading.Thread(target=main).start()
    bot.polling()
