#!/usr/bin/env python3
import io
import json
import os
import select
import socket
import subprocess
import stat
import tarfile
import tempfile
import time
from flask import Flask, request, send_file

def send(sock, msg):
	sock.send(bytes(json.dumps(msg) + '\n', 'iso-8859-1'))
	ready = select.select([sock], [], [], 600)

	if ready[0]:
		return receivemessage(sock)
	else:
		raise Exception("Could not get message from server")

def receivemessage(sock):
	data = ""
	ret = None
	while True:
		d = sock.recv(65536).decode('iso-8859-1')
		print("Received {}".format(d))
		data += d
		#data += sock.recv(1024).decode('iso-8859-1')
		if data.endswith('\n'):
			ret = json.loads(data)
			break

	return ret

def send_command(sock, command, args=None):
	message = {}
	message['command'] = command

	if args is not None:
		message['arguments'] = args

	return send(sock, message)

application = Flask(__name__)

working_directory = tempfile.TemporaryDirectory(dir="/dev/shm/")
logging_directory = tempfile.TemporaryDirectory(dir=working_directory.name)

unix_sock_path = os.path.join(working_directory.name, "suricata.sock")
read_sock_path = os.path.join(logging_directory.name, "eve.sock")

suricata_process = subprocess.Popen(['suricata', '-c', './config/suricata.yaml', '--unix-socket={}'.format(unix_sock_path)], stdout=subprocess.DEVNULL)

#Create the socket that we'll read from and connect to it
read_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
read_sock.bind(read_sock_path)
read_sock.settimeout(10)

#Wait for the suricata process to start up
suricata_sock = None
while suricata_sock is None:
	try:
		if stat.S_ISSOCK(os.stat(unix_sock_path).st_mode):
			suricata_sock = socket.socket(socket.AF_UNIX)
			suricata_sock.connect(unix_sock_path)
			suricata_sock.settimeout(10)

			#Apparently we have to send a version when we connect or suricata won't accept commands
			send(suricata_sock, {"version": '0.2'})
		else:
			raise FileNotFoundError()
	except FileNotFoundError:
		print("Waiting for {} to exist".format(unix_sock_path))
		time.sleep(1.0)


@application.route('/metadata', methods=['POST'])
@application.route('/full', methods=['POST'])
def handle_request():
	messages = []
	file_hashes = []
	with tempfile.NamedTemporaryFile(dir=working_directory.name, suffix='.pcap') as f:
		f.write(request.get_data())
		#TODO: logging

		pcap_file_args = {'output-dir': logging_directory.name, 'filename': f.name}
		send_command(suricata_sock, 'pcap-file', pcap_file_args)

		#Poll the socket until it's done processing packets
		ret = send_command(suricata_sock, 'pcap-file-number')
		while ret['message'] > 0:
			time.sleep(0.1)
			ret = send_command(suricata_sock, 'pcap-file-number')

		try:
			while True:
				msg = receivemessage(read_sock)
				messages.append(msg)

				if 'event_type' in msg and msg['event_type'] == 'fileinfo':
					#We need to keep track of extracted file paths so we can send them back later
					file_hashes.append(msg['fileinfo']['sha256'])

				if 'event_type' in msg and msg['event_type'] == 'stats':
					#The "stats" message seems to be the last one
					# (which makes sense as the information contained is only available after the pcap is done being processed)
					break
		except socket.timeout:
			#Never even received a stats message
			pass

		if request.path.startswith('/full'):
			#Requested the files as well. We need to return a tar file containing all extracted files and a json file of metadata
			tar_file_obj = io.BytesIO()
			tar_file = tarfile.open(fileobj=tar_file_obj, mode='w')

			for file_hash in file_hashes:
				#Files are stored in a directory under <logging_directory>/files/<first 2 bytes of hash>/<hash>
				file_path = os.path.join(logging_directory.name, 'files', file_hash[0:2], file_hash)
				with open(file_path, 'rb') as file_path_obj:
					tar_file.addfile(tar_file.gettarinfo(arcname=file_hash, fileobj=file_path_obj), file_path_obj)

			eve_obj = io.BytesIO()
			eve_obj.write(json.dumps(messages).encode('utf-8'))

			eve_obj_tarinfo = tarfile.TarInfo(name="metadata.json")
			eve_obj_tarinfo.size = eve_obj.tell()
			eve_obj.seek(0)

			tar_file.addfile(tarinfo=eve_obj_tarinfo, fileobj=eve_obj)
			eve_obj.close()

			tar_file_obj.seek(0)
			return send_file(tar_file_obj, attachment_filename="suricata_output.tar")

	return json.dumps(messages)

if __name__ == '__main__':
	application.run()
