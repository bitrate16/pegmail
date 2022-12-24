# pegmail: single-script SMTP server
# Copyright (C) 2022 bitrate16
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.


import aiosmtpd.controller
import aiosmtpd.handlers

import mimetypes
import argparse
import asyncio
import aiohttp
import secrets
import sqlite3
import atexit
import email
import json
import time
import sys
import ssl
import os

import email.message
import email.header

import aiohttp.web

import aiosmtpd.smtp

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#                               G L O B A L S
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Database connection
conn: sqlite3.Connection = None
lock: asyncio.Lock = None

# Web app
api_app: aiohttp.web.Application = None

# Args
args: dict = None

# SSL Context
context: ssl.SSLContext = None

# Config
DEBUG_LOG = False


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#                                C L A S S E S
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

class CustomController(aiosmtpd.controller.Controller):
	def factory(self):
		if context is not None:
			return aiosmtpd.smtp.SMTP(self.handler, require_starttls=True, tls_context=context)
		else:
			return aiosmtpd.smtp.SMTP(self.handler)

class CustomHandler:
	# async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
	# 	print('aaaaaaaaaaa')

	async def handle_DATA(self, server: aiosmtpd.smtp.SMTP, session: aiosmtpd.smtp.Session, envelope: aiosmtpd.smtp.Envelope):
		timestamp = round(time.time() * 1000)

		# Check for allowed domains
		match = False
		for to in envelope.rcpt_tos or []:
			pair = to.split('@')
			if len(pair) == 2 and pair[1] in args.server_host:
				match = True
				break

		# Not allowed
		if not match:
			return '553'

		# Keep track of the created files to clean in case of error
		allocated_files = []

		# Payload processing
		def iterate_payload(obj, depth=0):

			if isinstance(obj, email.message.Message):
				# Check for attachment
				if obj.get_content_disposition() == 'attachment' and obj.get_filename() is not None:
					hash = secrets.token_hex(args.file_hash_length)
					allocated_files.append({
						'hash': hash,
						'filename': obj.get_filename()
					})
					path = os.path.join(args.media_path, hash[:2], hash[2:4], hash[4:6])
					os.makedirs(path)
					path = os.path.join(path, hash[6:])
					with open(path, 'wb') as f:
						file_size = f.write(obj.get_payload(decode=True))

					return {
						'type': 'attachment',
						'hash': hash,
						'filename': obj.get_filename(),
						'mime': obj.get_content_type(),
						'size': file_size
					}

				elif (obj.get_content_type() is not None and obj.get_content_type().startswith('text/')) and obj.get_filename() is None:
					text = obj.get_payload(decode=True).decode('utf-8')
					return {
						'type': 'text',
						'mime': obj.get_content_type(),
						'text': text,
						'size': len(text)
					}

				elif obj.is_multipart():
					return {
						'type': obj.get_content_subtype(),
						'items': iterate_payload(obj.get_payload(), depth + 1)
					}

				# TODO: INLINE

				else:
					print('ERROR: Unsupported message')
					print(json.dumps({ k: obj.get(k, None) for k in obj.keys() }, indent=2))
					raise ValueError('Unsupported message')

			elif isinstance(obj, list):
				return [ iterate_payload(o, depth + 1) for o in obj ]

			else:
				return str(obj)

		mail_object: email.message.Message = email.message_from_bytes(envelope.original_content)

		try:
			mail_body = iterate_payload(mail_object)
		except:
			import traceback
			traceback.print_exc()

			# Cleanup
			for file in allocated_files:
				try:
					hash = file['hash']
					path = os.path.join(args.media_path, hash[:2], hash[2:4], hash[4:6], hash[6:])
					os.remove(path)
				except:
					pass

			# Return error
			return '451'

		# Serialize message to database
		mail_from = envelope.mail_from
		mail_to = envelope.rcpt_tos
		mail_subject = mail_object.get('Subject', None)
		try:
			mail_subject, mail_subject_encoding = email.header.decode_header(mail_subject)[0]
			mail_subject = mail_subject.decode(mail_subject_encoding)
		except:
			pass
		conn_peer = session.peer[0]
		host_name = session.host_name


		if DEBUG_LOG:
			print('> > > > > > > > MAIL > > > > > > > >')
			print('mail_from', mail_from)
			print('mail_to', mail_to)
			print('mail_subject', mail_subject)
			print('conn_peer', conn_peer)
			print('host_name', host_name)
			print('> > > > > > > > HDRS > > > > > > > >')
			for k in mail_object.keys():
				print(f'{ k }: "{ mail_object[k] }"')
			print('< < < < < < < < HDRS < < < < < < < <')
			print('> > > > > > > > BODY > > > > > > > >')
			print(json.dumps(mail_body, indent=2))
			print('< < < < < < < < BODY < < < < < < < <')
			print('< < < < < < < < MAIL < < < < < < < <')


		try:
			async with lock:
				mail_id = conn.execute(
					'INSERT INTO mail (timestamp, host_name, conn_peer, mail_from, mail_to, mail_subject, mail_body, mail_headers, is_read) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
					(
						timestamp,
						None if host_name is None else str(host_name),
						None if conn_peer is None else str(conn_peer),
						None if mail_from is None else str(mail_from),
						None if mail_to is None else json.dumps(mail_to),
						None if mail_subject is None else str(mail_subject),
						None if mail_body is None else json.dumps(mail_body),
						json.dumps({ k: mail_object.get(k, None) for k in mail_object.keys() })
					)
				).lastrowid

				# Append filedata to database
				for file in allocated_files:
					conn.execute('INSERT INTO mail_attachment (mail_id, hash, filename) VALUES (?, ?, ?)', (mail_id, file['hash'], file['filename']))

				conn.commit()
		except:
			import traceback
			traceback.print_exc()

			# Cleanup
			for file in allocated_files:
				try:
					hash = file['hash']
					path = os.path.join(args.media_path, hash[:2], hash[2:4], hash[4:6], hash[6:])
					os.remove(path)
				except:
					pass

			# Return error
			return '451'

		# Return OK
		return '250 OK'


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#                                    A P I
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

async def api__get_auth(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Auth MAIL suer based on `HOST` in `RCPT To`
	"""

	if DEBUG_LOG:
		print('> > > > > > > > AUTH > > > > > > > >')
		print('> > > > > > > > HDRS > > > > > > > >')
		for h in request.headers.keys():
			print(f'{ h }: "{ request.headers[h] }"')
		print('< < < < < < < < HDRS < < < < < < < <')
		print('< < < < < < < < AUTH < < < < < < < <')

	try:
		rcpt_to_header = request.headers['Auth-SMTP-To']
		rcpt_to = rcpt_to_header.split(':')[1][2:-1]

		if rcpt_to.split('@')[1] in args.server_host:
			return aiohttp.web.Response(
				headers={
					'Auth-Status': 'OK',
					'Auth-Server': args.server_addr,
					'Auth-Port': str(args.smtp_port)
				}
			)
		else:
			return aiohttp.web.Response(
				headers={
					'Auth-Status': 'Not allowed',
					'Auth-Wait': '0'
				}
			)
	except:
		return aiohttp.web.Response(
			headers={
				'Auth-Status': 'Not allowed',
				'Auth-Wait': '0'
			}
		)

async def api__get_media(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Get media by hash

	Guess Content-Type by file name and add Content-Disposition to force file name
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	try:
		hash = request.query['hash']

		async with lock:
			filename = conn.execute('SELECT filename FROM mail_attachment WHERE hash = ?', (hash,)).fetchall()[0][0]

		headers = {}
		path = os.path.join(args.media_path, hash[:2], hash[2:4], hash[4:6], hash[6:])

		ct, encoding = mimetypes.guess_type(filename)
		if not ct:
			ct = "application/octet-stream"

		if encoding:
			headers[aiohttp.hdrs.CONTENT_ENCODING] = encoding
		headers[aiohttp.hdrs.CONTENT_TYPE] = ct
		headers[aiohttp.hdrs.CONTENT_DISPOSITION] = f'inline; filename="{ filename }"'

		return aiohttp.web.FileResponse(path, headers=headers)
	except:
		raise aiohttp.web.HTTPNotFound()

async def api__get_mail(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Get mail by id

	Returns:
		timestamp: int
		mail_from: str
		mail_to: [str]
		mail_subject: str
		mail_body: json
		mail_headers: json
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	try:
		mail_id = int(request.query['mail_id'])
		async with lock:
			result = conn.execute('SELECT timestamp, mail_from, mail_to, mail_subject, is_read, mail_body, mail_headers FROM mail WHERE id = ?', (mail_id,)).fetchall()
		result = result[0]
		timestamp = result[0]
		mail_from = result[1]
		mail_to = None if result[2] is None else json.loads(result[2])
		mail_subject = result[3]
		is_read = result[4]
		mail_body = None if result[5] is None else json.loads(result[5])
		mail_headers = None if result[6] is None else json.loads(result[6])

		return aiohttp.web.json_response({
			'timestamp': timestamp,
			'mail_id': mail_id,
			'mail_from': mail_from,
			'mail_to': mail_to,
			'mail_subject': mail_subject,
			'is_read': is_read,
			'mail_body': mail_body,
			'mail_headers': mail_headers,
		})
	except:
		import traceback
		traceback.print_exc()
		return aiohttp.web.json_response({
			'error': 'invalid mail_id'
		})

async def api__get_count(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Get count of mails
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	async with lock:
		return aiohttp.web.json_response({
			'count': conn.execute('SELECT COUNT(*) FROM mail').fetchall()[0][0]
		})

async def api__get_list(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Get mail list starting with offset for count

	Params:
		count: int
		offset: int
		reverse: [0, 1]

	Returns:
		timestamp: int
		mail_id: int
		mail_from: str
		mail_to: [str]
		mail_subject: str
		mail_body: json
		mail_headers: json

		count: int
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	# Check values
	try:
		offset = request.query.get('offset', None)
		if offset is not None:
			offset = offset.strip()
			if offset == '':
				offset = None
			else:
				offset = int(offset)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid offset'
		})

	try:
		count = request.query.get('count', None)
		if count is not None:
			count = count.strip()
			if count == '':
				count = None
			else:
				count = int(count)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid count'
		})

	reverse = request.query.get('reverse', None) == '1'

	# Construct query prefix
	query_postfix = ''
	if reverse:
		query_postfix += ' ORDER BY id DESC'

	if count is not None and count >= 0:
		query_postfix += f' LIMIT { count }'
	else:
		query_postfix += ' LIMIT -1'

	if offset is not None and offset >= 0:
		query_postfix += f' OFFSET { offset }'

	# Query db
	async with lock:
		result = conn.execute(f'SELECT timestamp, id, mail_from, mail_to, mail_subject, is_read, mail_body, mail_headers FROM mail { query_postfix }').fetchall()
		result_count = conn.execute('SELECT COUNT(*) FROM mail').fetchall()[0][0]

	items = []
	for mail in result:
		timestamp = mail[0]
		mail_id = mail[1]
		mail_from = mail[2]
		mail_to = None if mail[3] is None else json.loads(mail[3])
		mail_subject = mail[4]
		is_read = mail[5]
		mail_body = None if mail[6] is None else json.loads(mail[6])
		mail_headers = None if mail[7] is None else json.loads(mail[7])

		items.append({
			'timestamp': timestamp,
			'mail_id': mail_id,
			'mail_from': mail_from,
			'mail_to': mail_to,
			'mail_subject': mail_subject,
			'is_read': is_read,
			'mail_body': mail_body,
			'mail_headers': mail_headers,
		})

	return aiohttp.web.json_response({
		'items': items,
		'count': result_count
	})

async def api__get_list_short(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Get mail list starting with offset for count without body

	Params:
		count: int
		offset: int
		reverse: [0, 1]

	Returns:
		timestamp: int
		mail_id: int
		mail_from: str
		mail_to: [str]
		mail_subject: str

		count: int
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	# Check values
	try:
		offset = request.query.get('offset', None)
		if offset is not None:
			offset = offset.strip()
			if offset == '':
				offset = None
			else:
				offset = int(offset)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid offset'
		})

	try:
		count = request.query.get('count', None)
		if count is not None:
			count = count.strip()
			if count == '':
				count = None
			else:
				count = int(count)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid count'
		})

	reverse = request.query.get('reverse', None) == '1'

	# Construct query prefix
	query_postfix = ''
	if reverse:
		query_postfix += ' ORDER BY id DESC'

	if count is not None and count >= 0:
		query_postfix += f' LIMIT { count }'
	else:
		query_postfix += ' LIMIT -1'

	if offset is not None and offset >= 0:
		query_postfix += f' OFFSET { offset }'

	# Query db
	async with lock:
		result = conn.execute(f'SELECT timestamp, id, mail_from, mail_to, mail_subject, is_read FROM mail { query_postfix }').fetchall()
		result_count = conn.execute('SELECT COUNT(*) FROM mail').fetchall()[0][0]

	items = []
	for mail in result:
		timestamp = mail[0]
		mail_id = mail[1]
		mail_from = mail[2]
		mail_to = None if mail[3] is None else json.loads(mail[3])
		mail_subject = mail[4]
		is_read = mail[5]

		items.append({
			'timestamp': timestamp,
			'mail_id': mail_id,
			'mail_from': mail_from,
			'mail_to': mail_to,
			'mail_subject': mail_subject,
			'is_read': is_read,
		})

	return aiohttp.web.json_response({
		'items': items,
		'count': result_count
	})

async def api__get_search_count(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Get count of mails

	Params:
		filter_mail_to: str
		filter_mail_from: str
		filter_mail_subject: str
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	# Filter options
	query_params = []

	filter_mail_to = request.query.get('filter_mail_to', None)
	if filter_mail_to is None:
		filter_mail_to = ''
	filter_mail_to = filter_mail_to.strip().lower()
	if filter_mail_to == '':
		query_filter_mail_to = '1'
	else:
		filter_mail_to = '%"%' + filter_mail_to.replace('%', '[%]') + '%"%'
		query_filter_mail_to = 'mail_to IS NOT NULL AND LOWER(mail_to) LIKE ?'
		query_params.append(filter_mail_to)

	filter_mail_from = request.query.get('filter_mail_from', None)
	if filter_mail_from is None:
		filter_mail_from = ''
	filter_mail_from = filter_mail_from.strip().lower()
	if filter_mail_from == '':
		query_filter_mail_from = '1'
	else:
		filter_mail_from = '%' + filter_mail_from.replace('%', '[%]') + '%'
		query_filter_mail_from = 'mail_from IS NOT NULL AND LOWER(mail_from) LIKE ?'
		query_params.append(filter_mail_from)

	filter_mail_subject = request.query.get('filter_mail_subject', None)
	if filter_mail_subject is None:
		filter_mail_subject = ''
	filter_mail_subject = filter_mail_subject.strip().lower()
	if filter_mail_subject == '':
		query_filter_mail_subject = '1'
	else:
		filter_mail_subject = '%' + filter_mail_subject.replace('%', '[%]') + '%'
		query_filter_mail_subject = 'mail_subject IS NOT NULL AND LOWER(mail_subject) LIKE ?'
		query_params.append(filter_mail_subject)

	async with lock:
		return aiohttp.web.json_response({
			'count': conn.execute(f'SELECT COUNT(*) FROM mail WHERE { query_filter_mail_to } AND { query_filter_mail_from } AND { query_filter_mail_subject }', query_params).fetchall()[0][0]
		})

async def api__get_search_list(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Search mail list starting with offset for count.
	Filter mails by containing specified substring in `mail_from`, one of `mail_to` and `mail_subject`

	Params:
		count: int
		offset: int
		reverse: [0, 1]
		filter_mail_to: str
		filter_mail_from: str
		filter_mail_subject: str
		filter_is_read: [0, 1] - default any

	Returns:
		timestamp: int
		mail_id: int
		mail_from: str
		mail_to: [str]
		mail_subject: str
		mail_body: json
		mail_headers: json

		count: int
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	# Check values
	try:
		offset = request.query.get('offset', None)
		if offset is not None:
			offset = offset.strip()
			if offset == '':
				offset = None
			else:
				offset = int(offset)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid offset'
		})

	try:
		count = request.query.get('count', None)
		if count is not None:
			count = count.strip()
			if count == '':
				count = None
			else:
				count = int(count)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid count'
		})

	reverse = request.query.get('reverse', None) == '1'

	# Filter options
	query_params = []

	filter_mail_to = request.query.get('filter_mail_to', None)
	if filter_mail_to is None:
		filter_mail_to = ''
	filter_mail_to = filter_mail_to.strip().lower()
	if filter_mail_to == '':
		query_filter_mail_to = '1'
	else:
		filter_mail_to = '%"%' + filter_mail_to.replace('%', '[%]') + '%"%'
		query_filter_mail_to = 'mail_to IS NOT NULL AND LOWER(mail_to) LIKE ?'
		query_params.append(filter_mail_to)

	filter_mail_from = request.query.get('filter_mail_from', None)
	if filter_mail_from is None:
		filter_mail_from = ''
	filter_mail_from = filter_mail_from.strip().lower()
	if filter_mail_from == '':
		query_filter_mail_from = '1'
	else:
		filter_mail_from = '%' + filter_mail_from.replace('%', '[%]') + '%'
		query_filter_mail_from = 'mail_from IS NOT NULL AND LOWER(mail_from) LIKE ?'
		query_params.append(filter_mail_from)

	filter_mail_subject = request.query.get('filter_mail_subject', None)
	if filter_mail_subject is None:
		filter_mail_subject = ''
	filter_mail_subject = filter_mail_subject.strip().lower()
	if filter_mail_subject == '':
		query_filter_mail_subject = '1'
	else:
		filter_mail_subject = '%' + filter_mail_subject.replace('%', '[%]') + '%'
		query_filter_mail_subject = 'mail_subject IS NOT NULL AND LOWER(mail_subject) LIKE ?'
		query_params.append(filter_mail_subject)

	filter_is_read = request.query.get('filter_is_read', None)
	if filter_is_read in [ '0', '1' ]:
		query_filter_is_read = 'is_read = ?'
		query_params.append(filter_is_read)
	else:
		query_filter_is_read = '1'

	# Construct query prefix
	query_postfix = ''
	if reverse:
		query_postfix += ' ORDER BY id DESC'

	if count is not None and count >= 0:
		query_postfix += f' LIMIT { count }'
	else:
		query_postfix += ' LIMIT -1'

	if offset is not None and offset >= 0:
		query_postfix += f' OFFSET { offset }'

	# Query db
	async with lock:
		result = conn.execute(f'SELECT timestamp, id, mail_from, mail_to, mail_subject, is_read, mail_body, mail_headers FROM mail WHERE { query_filter_mail_to } AND { query_filter_mail_from } AND { query_filter_mail_subject } AND { query_filter_is_read } { query_postfix }', query_params).fetchall()
		result_count = conn.execute(f'SELECT COUNT(*) FROM mail WHERE { query_filter_mail_to } AND { query_filter_mail_from } AND { query_filter_mail_subject } AND { query_filter_is_read }', query_params).fetchall()[0][0]

	items = []
	for mail in result:
		timestamp = mail[0]
		mail_id = mail[1]
		mail_from = mail[2]
		mail_to = None if mail[3] is None else json.loads(mail[3])
		mail_subject = mail[4]
		is_read = mail[5]
		mail_body = None if mail[6] is None else json.loads(mail[6])
		mail_headers = None if mail[7] is None else json.loads(mail[7])

		items.append({
			'timestamp': timestamp,
			'mail_id': mail_id,
			'mail_from': mail_from,
			'mail_to': mail_to,
			'mail_subject': mail_subject,
			'is_read': is_read,
			'mail_body': mail_body,
			'mail_headers': mail_headers,
		})

	return aiohttp.web.json_response({
		'items': items,
		'count': result_count
	})

async def api__get_search_list_short(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Search mail list starting with offset for count.
	Filter mails by containing specified substring in `mail_from`, one of `mail_to` and `mail_subject`

	Params:
		count: int
		offset: int
		reverse: [0, 1]
		filter_mail_to: str
		filter_mail_from: str
		filter_mail_subject: str

	Returns:
		timestamp: int
		mail_id: int
		mail_from: str
		mail_to: [str]
		mail_subject: str

		count: int
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})

	# Check values
	try:
		offset = request.query.get('offset', None)
		if offset is not None:
			offset = offset.strip()
			if offset == '':
				offset = None
			else:
				offset = int(offset)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid offset'
		})

	try:
		count = request.query.get('count', None)
		if count is not None:
			count = count.strip()
			if count == '':
				count = None
			else:
				count = int(count)
	except:
		return aiohttp.web.json_response({
			'error': 'invalid count'
		})

	reverse = request.query.get('reverse', None) == '1'

	# Filter options
	query_params = []

	filter_mail_to = request.query.get('filter_mail_to', None)
	if filter_mail_to is None:
		filter_mail_to = ''
	filter_mail_to = filter_mail_to.strip().lower()
	if filter_mail_to == '':
		query_filter_mail_to = '1'
	else:
		filter_mail_to = '%"%' + filter_mail_to.replace('%', '[%]') + '%"%'
		query_filter_mail_to = 'mail_to IS NOT NULL AND LOWER(mail_to) LIKE ?'
		query_params.append(filter_mail_to)

	filter_mail_from = request.query.get('filter_mail_from', None)
	if filter_mail_from is None:
		filter_mail_from = ''
	filter_mail_from = filter_mail_from.strip().lower()
	if filter_mail_from == '':
		query_filter_mail_from = '1'
	else:
		filter_mail_from = '%' + filter_mail_from.replace('%', '[%]') + '%'
		query_filter_mail_from = 'mail_from IS NOT NULL AND LOWER(mail_from) LIKE ?'
		query_params.append(filter_mail_from)

	filter_mail_subject = request.query.get('filter_mail_subject', None)
	if filter_mail_subject is None:
		filter_mail_subject = ''
	filter_mail_subject = filter_mail_subject.strip().lower()
	if filter_mail_subject == '':
		query_filter_mail_subject = '1'
	else:
		filter_mail_subject = '%' + filter_mail_subject.replace('%', '[%]') + '%'
		query_filter_mail_subject = 'mail_subject IS NOT NULL AND LOWER(mail_subject) LIKE ?'
		query_params.append(filter_mail_subject)

	filter_is_read = request.query.get('filter_is_read', None)
	if filter_is_read in [ '0', '1' ]:
		query_filter_is_read = 'is_read = ?'
		query_params.append(filter_is_read)
	else:
		query_filter_is_read = '1'

	# Construct query prefix
	query_postfix = ''
	if reverse:
		query_postfix += ' ORDER BY id DESC'

	if count is not None and count >= 0:
		query_postfix += f' LIMIT { count }'
	else:
		query_postfix += ' LIMIT -1'

	if offset is not None and offset >= 0:
		query_postfix += f' OFFSET { offset }'

	# Query db
	async with lock:
		result = conn.execute(f'SELECT timestamp, id, mail_from, mail_to, mail_subject, is_read FROM mail WHERE { query_filter_mail_to } AND { query_filter_mail_from } AND { query_filter_mail_subject } AND { query_filter_is_read } { query_postfix }', query_params).fetchall()
		result_count = conn.execute(f'SELECT COUNT(*) FROM mail WHERE { query_filter_mail_to } AND { query_filter_mail_from } AND { query_filter_mail_subject } AND { query_filter_is_read }', query_params).fetchall()[0][0]

	items = []
	for mail in result:
		timestamp = mail[0]
		mail_id = mail[1]
		mail_from = mail[2]
		mail_to = None if mail[3] is None else json.loads(mail[3])
		mail_subject = mail[4]
		is_read = mail[5]

		items.append({
			'timestamp': timestamp,
			'mail_id': mail_id,
			'mail_from': mail_from,
			'mail_to': mail_to,
			'mail_subject': mail_subject,
			'is_read': is_read,
		})

	return aiohttp.web.json_response({
		'items': items,
		'count': result_count
	})

async def api__get_set_read(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
	"""
	Set mail id_read state

	Params:
		mail_id: int
		read_state: [0, 1]
	"""

	if len(args.api_remote_address) and request.remote not in args.api_remote_address:
		return aiohttp.web.json_response({
			'error': 'not allowed'
		})


	try:
		mail_id = int(request.query['mail_id'])
	except:
		return aiohttp.web.json_response({
			'error': 'invalid mail_id'
		})

	is_read = request.query.get('is_read', None)
	if is_read not in [ '0', '1' ]:
		return aiohttp.web.json_response({
			'error': 'invalid is_read'
		})
	is_read = int(is_read)

	async with lock:
		rowcnt = conn.execute('UPDATE mail SET is_read = ? WHERE id = ?', (is_read, mail_id))
		conn.commit()

	if rowcnt == 0:
		return aiohttp.web.json_response({
			'error': 'invalid mail_id'
		})

	return aiohttp.web.json_response({
		'is_read': is_read
	})


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#                                   E N T R Y
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def dispose():
	print('Stopping MAIL server')
	conn.close()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='pegmail SMTP server')
	parser.add_argument('--file_hash_length', required=False, dest='file_hash_length', type=int, default=24, help='media file hash length')
	parser.add_argument('--media_path', required=False, dest='media_path', type=str, default='media', help='media folder path')
	parser.add_argument('--db_path', required=False, dest='db_path', type=str, default='mail.db', help='database path')
	parser.add_argument('--server_addr', required=False, dest='server_addr', type=str, default='127.0.0.1', help='server address for nginx to forward auth requests and mail traffic')
	parser.add_argument('--smtp_port', required=False, dest='smtp_port', type=int, default=25, help='SMTP server port')
	parser.add_argument('--api_port', required=False, dest='api_port', type=int, default=35, help='API server port')
	parser.add_argument('--ssl_cert', required=False, dest='ssl_cert', type=str, default=None, help='SSL certificate path (enables nginx proxy)')
	parser.add_argument('--ssl_key', required=False, dest='ssl_key', type=str, default=None, help='SSL key path (enables nginx proxy)')
	parser.add_argument('--server_host', required=False, dest='server_host', nargs='+', type=str, default=['example.com'], help='server host names user to filter incoming mail by mail_to')
	parser.add_argument('--generate_nginx_config', dest='generate_nginx_config', action='store_true', help='generate sample NGINX config')
	parser.add_argument('--api_remote_address', required=False, dest='api_remote_address', nargs='+', type=str, default=[], help='remote IPs used to restrict API access')
	parser.add_argument('--debug', required=False, dest='debug', action='store_true', help='enable debug logging')
	args = parser.parse_args()

	# Check values
	if len(args.server_host) == 0:
		print('Required at least one server_host')
		exit(0)

	# Generate sample nginx config & exit
	if args.generate_nginx_config:
		if args.ssl_cert is not None and args.ssl_key is not None:
			for host in args.server_host:
				print(f"""stream {{
    server {{
        listen 25;
        proxy_pass { args.server_addr }:{ args.smtp_port };
    }}
}}\n""")
		else:
			for host in args.server_host:
				print(f"""mail {{
    # Change to your DNS record
    server_name mx.{ host };

    auth_http http://{ args.server_addr }:{ args.api_port }/auth;

    starttls on;
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Change to your certificates path
    ssl_certificate     /etc/letsencrypt/live/{ host }/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{ host }/privkey.pem;

    server {{
        listen 25;
        protocol smtp;
        smtp_auth none;
        proxy on;
        proxy_pass_error_message on;
        xclient off;
    }}
}}\n""")
		exit(0)

	print('Starting MAIL server')

	if args.ssl_cert is not None and args.ssl_key is not None:
		print('Starting in self-ssl mode')
		context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		context.load_cert_chain(args.ssl_cert, args.ssl_key)
	else:
		print('Starting in nginx-ssl mode')
		context = None

	DEBUG_LOG = DEBUG_LOG or args.debug

	atexit.register(dispose)

	lock = asyncio.Lock()
	conn = sqlite3.connect(args.db_path, check_same_thread=False)
	conn.executescript("""
		-- Mail only data to track mail infos
		CREATE TABLE IF NOT EXISTS mail (
			id INTEGER PRIMARY KEY,

			-- Receive timestamp, ms
			timestamp INTEGER,

			-- Conn info
			host_name TEXT,
			conn_peer TEXT,

			-- mail_from: str - mail sender
			mail_from TEXT,

			-- mail_to: json - mail recipients list
			mail_to TEXT,

			-- mail_subject: str - mail subject
			mail_subject TEXT,

			-- mail_body: json - Mail contents
			mail_body TEXT,

			-- mail_headers: json - Mail headers
			mail_headers TEXT,

			-- is message read
			is_read INTEGER
		);

		-- Mail attachments
		CREATE TABLE IF NOT EXISTS mail_attachment (
			mail_id INTEGER,
			hash TEXT UNIQUE,
			filename TEXT
		);
	""")

	controller = CustomController(CustomHandler(), hostname='0.0.0.0' if sys.platform == 'linux' else '127.0.0.1', port=args.smtp_port)#, ssl_context=context)

	# API app
	api_app = aiohttp.web.Application()
	if not (args.ssl_cert is not None and args.ssl_key is not None):
		api_app.router.add_get('/auth', api__get_auth)
	api_app.router.add_get('/count', api__get_count)
	api_app.router.add_get('/media', api__get_media)
	api_app.router.add_get('/mail', api__get_mail)
	api_app.router.add_get('/list', api__get_list)
	api_app.router.add_get('/list_short', api__get_list_short)
	api_app.router.add_get('/search_count', api__get_search_count)
	api_app.router.add_get('/search_list', api__get_search_list)
	api_app.router.add_get('/search_list_short', api__get_search_list_short)
	api_app.router.add_get('/set_read', api__get_set_read)

	controller.start()
	aiohttp.web.run_app(api_app, port=args.api_port)
