pegmail - single-script SMTP server
-----------------------------------

Single-script SMTP server supporting E-MAIL receiving & REST JSON API with mailbox search, filter & read/unread state

Features:
---------

* Single-script server
* NGINX-compatible SMTP `/auth` endpoint that allows only matching `mail_to` recipients
* NGINX commandline configuration generator
* Configurable SMTP & API ports
* Configurable upstream IP & IP-based access for API
* JSON API for fetching messages, filtering by `mail_from`, `mail_to`, `subject`
* SQlite3 database & hash-tree-based file storage

Commandline
-----------

Server arguments:
```
usage: server.py [-h] [--file_hash_length FILE_HASH_LENGTH]
                 [--media_path MEDIA_PATH] [--db_path DB_PATH]
                 [--server_addr SERVER_ADDR] [--smtp_port SMTP_PORT]
                 [--api_port API_PORT] [--ssl_cert SSL_CERT] [--ssl_key SSL_KEY]
                 [--server_host SERVER_HOST [SERVER_HOST ...]]
                 [--generate_nginx_config]
                 [--api_remote_address API_REMOTE_ADDRESS [API_REMOTE_ADDRESS ...]]
                 [--debug]

pegmail SMTP server

optional arguments:
  -h, --help            show this help message and exit
  --file_hash_length FILE_HASH_LENGTH
                        media file hash length
  --media_path MEDIA_PATH
                        media folder path
  --db_path DB_PATH     database path
  --server_addr SERVER_ADDR
                        server address for nginx to forward auth requests and mail
                        traffic
  --smtp_port SMTP_PORT
                        SMTP server port
  --api_port API_PORT   API server port
  --ssl_cert SSL_CERT   SSL certificate path (enables nginx proxy)
  --ssl_key SSL_KEY     SSL key path (enables nginx proxy)
  --server_host SERVER_HOST [SERVER_HOST ...]
                        server host names user to filter incoming mail by mail_to
  --generate_nginx_config
                        generate sample NGINX config
  --api_remote_address API_REMOTE_ADDRESS [API_REMOTE_ADDRESS ...]
                        remote IPs used to restrict API access
  --debug               enable debug logging
```

*`--ssl_cert` and `--ssl_key` enables no-nginx mode and forces server to handle ssl context. Avoiding these arguments forces server to be behind nginx that should handle ssl context and use `/auth` endpoint for connection authorization.*

Endpoints
---------

> `/auth` - SMTP AUTH Procedure

> `/count` - Get total mail count

Returns:
```
{
	'count': 1234
}
```

> `/media?hash=...` - Get media attachment by hash

* *In addition to file contents, returns MIME-type for the file based on it's filename in mail*

> `mail?mail_id=...` - Get full message info by it's ID

Returns:
```
{
	'timestamp': 1234567
	'mail_id': 3,
	'mail_from': 'aboba@beb.ra'
	'mail_to': [ 'spam@am.am', 'vam@sp.am' ],
	'mail_subject': 'Here is my new SPAM collection',
	'is_read': 0,
	'mail_body': '...',
	'mail_headers': { 'DKIM-Signature': '...', ... }
}
```

> `/count` - Get total count of messages

> `/list?count=...&offset=...&reverse=...` - List messages

* *`reverse` is optional parameter and default is `0`*

Returns:
```
{
	'items': [
		{
			'timestamp': 1234567
			'mail_id': 3,
			'mail_from': 'aboba@beb.ra'
			'mail_to': [ 'spam@am.am', 'vam@sp.am' ],
			'mail_subject': 'Here is my new SPAM collection',
			'is_read': 0,
			'mail_body': '...',
			'mail_headers': { 'DKIM-Signature': '...', ... }
		},
		{
			...
		}
	],
	'count': 1234
}
```

> `/list_short?count=...&offset=...&reverse=...` - List short messages without headers and body

* *`reverse` is optional parameter and default is `0`*

Returns:
```
{
	'items': [
		{
			'timestamp': 1234567
			'mail_id': 3,
			'mail_from': 'aboba@beb.ra'
			'mail_to': [ 'spam@am.am', 'vam@sp.am' ],
			'mail_subject': 'Here is my new SPAM collection',
			'is_read': 0
		},
		{
			...
		}
	],
	'count': 1234
}
```

> `/filter_count?filter_mail_to=...&filter_mail_from=...&filter_mail_subject=...&filter_is_read=...` - Get count of messages matching filter

* *By default empty value mean no filter by given field*

Returns:
```
{
	'count': 432
}
```

> `/filter_list?filter_mail_to=...&filter_mail_from=...&filter_mail_subject=...&filter_is_read=...` - List messages matching filter

* *By default empty value mean no filter by given field*

Returns:
```
{
	'items': [
		{
			'timestamp': 1234567
			'mail_id': 3,
			'mail_from': 'aboba@beb.ra'
			'mail_to': [ 'spam@am.am', 'vam@sp.am' ],
			'mail_subject': 'Here is my new SPAM collection',
			'is_read': 0,
			'mail_body': '...',
			'mail_headers': { 'DKIM-Signature': '...', ... }
		},
		{
			...
		}
	],
	'count': 432
}
```

> `/filter_list_short?filter_mail_to=...&filter_mail_from=...&filter_mail_subject=...&filter_is_read=...` - List short messages without headers and body matching filter

* *By default empty value mean no filter by given field*

Returns:
```
{
	'items': [
		{
			'timestamp': 1234567
			'mail_id': 3,
			'mail_from': 'aboba@beb.ra'
			'mail_to': [ 'spam@am.am', 'vam@sp.am' ],
			'mail_subject': 'Here is my new SPAM collection',
			'is_read': 0
		},
		{
			...
		}
	],
	'count': 432
}
```

> `/set_read?mail_id=...&is_read=...` - Set message read state

Returns:
```
{
	'is_read': 1
}
```

LICENSE
-------

```
pegmail: single-script SMTP server
Copyright (C) 2022 bitrate16

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```