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
read_sock_path = os.path.join(logging_directory.name, "eve.sock")

suricata_process = subprocess.Popen(['suricata', '-c', './config/suricata.yaml', '--unix-socket={}'.format(unix_sock_path)], stdout=subprocess.DEVNULL)

#Create the socket that we'll read from and connect to it
read_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
read_sock.bind(read_sock_path)
read_sock.settimeout(0.5)

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
	messages = []
	with tempfile.NamedTemporaryFile(dir=working_directory.name, suffix='.pcap') as f:
		f.write(request.get_data())
		#TODO: logging

		pcap_file_args = {'output-dir': logging_directory.name, 'filename': f.name}
		suricata_sc.send_command('pcap-file', pcap_file_args)

		#Poll the socket until it's done processing packets
		ret = suricata_sc.send_command('pcap-file-number')
		while ret['message'] > 0:
			ret = suricata_sc.send_command('pcap-file-number')
			time.sleep(0.1)

		try:
			while True:
				messages.append(json.loads(read_sock.recv(65536).decode("utf-8")))
		except socket.timeout:
			pass

	return json.dumps(messages)

if __name__ == '__main__':
	application.run()
