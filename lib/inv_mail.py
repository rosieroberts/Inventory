#!/usr/bin/env python3

from socket import gethostbyname, gaierror
from smtplib import SMTP, SMTPConnectError
from logging import FileHandler, Formatter, StreamHandler, getLogger, INFO
from configparser import ConfigParser
from email.message import EmailMessage
from datetime import date
from json2html import *

logger = getLogger('email')
# TODO: set to ERROR later on after setup
logger.setLevel(INFO)

file_formatter = Formatter('{asctime} {name}: {message}', style='{')
stream_formatter = Formatter('{message}', style='{')

today = date.today()
# logfile
file_handler = FileHandler('/opt/Inventory/logs/asset_inventory{}.log'
                           .format(today.strftime('%m%d%Y')))
file_handler.setLevel(INFO)
file_handler.setFormatter(file_formatter)

# console
stream_handler = StreamHandler()
stream_handler.setFormatter(stream_formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)


def send_mail(start,
              runtime,
              clubs,
              club_queue,
              scan_queue,
              not_scanned,
              api_status,
              added,
              restored,
              updated,
              deleted):

    scanned_a = []
    scanned_r = []
    scanned_d = []
    scanned_u = []
    clubs_s = []
    clubs_n = []
    clubs_q = []
    api_errors = []
    asset_errors = []

    if api_status:
        for item in api_status:
            if item['status'] == 'error':
                api_errors.append(item['asset_tag'])

    for item in added:
        a = {'Clubs': item[0],
             'Added': item[1]}
        scanned_a.append(a)

    for item in restored:
        r = {'Clubs': item[0],
             'Restored': item[1]}
        scanned_r.append(r)

    for item in updated:
        u = {'Clubs': item[0],
             'Updated': item[1]}
        scanned_u.append(u)

    for item in deleted:
        d = {'Clubs': item[0],
             'Deleted': item[1]}
        scanned_d.append(d)

    for item in clubs:
        s = {'Clubs': item}
        clubs_s.append(s)

    for item in not_scanned:
        n = {'Clubs': item}
        clubs_n.append(n)

    for item in club_queue:
        q = {'Clubs': item}
        clubs_q.append(q)

    for item in api_errors:
        e = {'Asset': item}
        asset_errors.append(e)

    table = json2html.convert(json=scanned_a)
    table2 = json2html.convert(json=scanned_r)
    table3 = json2html.convert(json=scanned_u)
    table4 = json2html.convert(json=scanned_d)

    clubs_conn = json2html.convert(json=clubs_s)
    clubs_ncon = json2html.convert(json=clubs_n)
    clubs_queue = json2html.convert(json=clubs_q)
    api_error = json2html.convert(json=asset_errors)

    if not clubs:
        scan_error = ''
    else:
        scan_error = 'No'

    # Create the base text message.
    config = ConfigParser()
    config.read('/opt/Inventory/lib/config.cnf')
    config.sections()
    website = config['mail']['website']

    msg = EmailMessage()
    msg['Subject'] = 'Information Security Asset Inventory'
    msg['From'] = config['mail']['sender']
    msg['To'] = config['mail']['recipient']

    msg.set_content("""\
    Hello,

    Below is the report for this week's Asset Inventory Scan:


    """)

    # Add the html version.  This converts the message into a multipart/alternative
    # container, with the original text message as the first part and the new html
    # message as the second part.
    msg.add_alternative("""\
    <html>
      <head></head>
      <body>
        <p>Hello,</p>
        <p>Below is the report for this week's Asset Inventory Scan:</p>

            <ul>
            <li>Scan started at {start}</p>
            <li>Runtime: {runtime}</li>
            <li>{scan_error} Errors Running Script</li>
            <li>{api_errors} Errors with Snipe-IT API</li>
            <li>{club_count} clubs were successfully scanned</li>
            <li>{scan_queue} clubs were not scanned</li>
            <li>{not_con_count} clubs were not scanned because of a problem</li>
            <li>{added_count} assets were added to snipe_it</li>
            <li>{restored_count} assets were restored in snipe_it</li>
            <li>{updated_count} assets were updated in snipe_it</li>
            <li>{deleted_count} assets were deleted from snipe_it</li></ul>
            <p>More detailed information:</p>
            {website}
        </p>
      </body>
    </html>
    """.format(club_count=len(clubs),
               scan_queue=len(scan_queue),
               not_con_count=len(not_scanned),
               added_count=len(added),
               restored_count=len(restored),
               updated_count=len(updated),
               deleted_count=len(deleted),
               api_errors=len(api_errors),
               scan_error=scan_error,
               start=start,
               runtime=runtime,
               website=website), subtype='html')

    msg2 = """\
    <html>
      <head></head>
      <body>
        <p>Hello,</p>
        <p>Below is the report for this week's Asset Inventory Scan:</p>

            <ul>
            <li>Scan started at {start}</p>
            <li>Runtime: {runtime}</li>
            <li>{scan_error} Errors running script</li>
            <li>{api_errors} Errors with Snipe-IT API</li>
            <li>{club_count} clubs were successfully scanned</li>
            <li>{scan_queue} clubs were not scanned</li>
            <li>{not_con_count} clubs were not scanned because of a problem</li>
            <li>{added_count} assets were added to snipe_it</li>
            <li>{restored_count} assets were restored in snipe_it</li>
            <li>{updated_count} assets were updated in snipe_it</li>
            <li>{deleted_count} assets were deleted from snipe_it</li></ul>
            <p>More detailed information:</p>
               <p>Clubs Scanned:</p>
               {clubs_conn}
               <p>Clubs Not Scanned:</p>
               {clubs_queue}
               <p>Clubs Not Scanned because of a problem:</p>
               {clubs_ncon}
               <p>Assets Added:</p>
               {table}
               <p>Assets Restored:</p>
               {table2}
               <p>Assets Updated:</p>
               {table3}
               <p>Assets Deleted:</p>
               {table4}
               <p>Tags with API errors</p>
               {api_error}

        </p>
      </body>
    </html>
    """.format(club_count=len(clubs),
               scan_queue=len(scan_queue),
               not_con_count=len(not_scanned),
               added_count=len(added),
               restored_count=len(restored),
               updated_count=len(updated),
               deleted_count=len(deleted),
               api_errors=len(api_errors),
               api_error=api_error,
               scan_error=scan_error,
               start=start,
               runtime=runtime,
               table=table,
               table2=table2,
               table3=table3,
               table4=table4,
               clubs_conn=clubs_conn,
               clubs_queue=clubs_queue,
               clubs_ncon=clubs_ncon)

    # Make a local copy of what we are going to send.
    with open('/opt/Inventory/logs/outgoing.msg', 'wb') as f:
        f.write(bytes(msg))

    with open('/var/www/html/inv.html', 'w') as f2:
        f2.write(msg2)
        f2.close()

    try:
        # Send the message via SMTP server.
        with SMTP(gethostbyname(config['mail']['server'])) as s:
            s.send_message(msg)
            logger.info('Email message sent successfully')
            return(msg)

    except gaierror:
        logger.exception('Hostname resolution has failed', config['mail']['server'])
        exit()

    except SMTPConnectError:
        logger.exception('Unable to connect to {}, the server refused the connection'.format(s))
