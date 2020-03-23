#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import stat
import tempfile
import time
from flask import Flask, request
from suricata.sc import SuricataSC #TODO: I had to copy /usr/lib/python3.6/site-packages/suricata/ to the virtualenv to get this to work. Don't know how to install the python package to the virtualenv

application = Flask(__name__)

working_directory = tempfile.TemporaryDirectory(dir="/dev/shm/")
logging_directory = tempfile.TemporaryDirectory(dir=working_directory.name)
unix_sock_path = os.path.join(working_directory.name, "suricata.sock")

suricata_process = subprocess.Popen(['suricata', '-c', './config/suricata.yaml', '--unix-socket={}'.format(unix_sock_path)])

#Wait for the suricata process to start up
suricata_sc = None
while suricata_sc is None:
	try:
		if stat.S_ISSOCK(os.stat(unix_sock_path).st_mode):
			suricata_sc = SuricataSC(unix_sock_path)
			suricata_sc.connect()
		else:
			raise FileNotFoundError()
	except FileNotFoundError:
		print("Waiting for {} to exist".format(unix_sock_path))
		time.sleep(1.0)

@application.route('/suricata', methods=['POST'])
def handle_request():
	with tempfile.NamedTemporaryFile(dir=working_directory.name, suffix='.pcap') as f:
		f.write(request.get_data())
		#TODO: logging

		command, args = suricata_sc.parse_command('pcap-file {} {}'.format(f.name, logging_directory.name))
		suricata_sc.send_command(command, args)

		command, args = suricata_sc.parse_command('pcap-file-number')
		ret = suricata_sc.send_command(command, args)

		#Poll the socket until it's done processing packets
		while ret['message'] > 0:
			ret = suricata_sc.send_command(command, args)
			time.sleep(0.1)

		#TODO: read the eve.json and send it back

	return str(ret)

if __name__ == '__main__':
	application.run()
