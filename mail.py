#!/usr/bin/env python3

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import smtplib
from socket import gethostbyname
import mac as inv
import config as cfg


sender = cfg.sender
recipients = cfg.recipients
mailbody = cfg.mailbody

def MailSend(sender, recipients, mailbody):
    """Simple function to send mail."""
    msg = MIMEMultipart()
    msg['Subject'] = 'Inventory CSV File'
    msg['From'] = 'IT Security'
    msg['To'] = recipients

    msg.attach(MIMEText(mailbody, 'plain'))

    attachment = 'inventory10-18.csv'
    f = open(attachment, 'rb')

    part = MIMEBase('application', 'octet_stream')
    part.set_payload((attachment).read())

    part.add_header('Content-Disposition', 'attachment: filename=' +filename)
    msg.attach(part)
    text = msg.as_string()

    s = smtplib.SMTP(gethostbyname(cfg.mailhost), '25')
    s.sendmail(sender, recipients, text)
    s.quit

MailSend(sender, recipients, mailbody)
