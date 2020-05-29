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
		#Suricata doesn't seem to have standardized on a naming convention for arguments yet
		if not isinstance(args, dict):
			message['arguments'] = {'variable': args}
		else:
			message['arguments'] = args

	print("Sending {}".format(json.dumps(message)))
	
	return send(sock, message)

application = Flask(__name__)

working_directory = tempfile.TemporaryDirectory(dir="/dev/shm/")
os.mkdir(os.path.join(working_directory.name, "logs"))

command_sock_path = os.path.join(working_directory.name, "suricata.sock")
output_sock_path = os.path.join(working_directory.name, "logs", "eve.sock")

suricata_process = subprocess.Popen(['suricata', '-c', './config/suricata.yaml', '--unix-socket={}'.format(command_sock_path)], stdout=subprocess.DEVNULL)

#Create the socket that we'll read from and connect to it
output_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
output_sock.bind(output_sock_path)
output_sock.settimeout(10)

#Wait for the suricata process to start up
command_sock = None
while command_sock is None:
	try:
		if stat.S_ISSOCK(os.stat(command_sock_path).st_mode):
			command_sock = socket.socket(socket.AF_UNIX)
			command_sock.connect(command_sock_path)
			command_sock.settimeout(10)

			#Apparently we have to send a version when we connect or suricata won't accept commands
			send(command_sock, {"version": '0.2'})
		else:
			raise FileNotFoundError()
	except FileNotFoundError:
		print("Waiting for {} to exist".format(command_sock_path))
		time.sleep(1.0)

def process_pcap(pcap_file, get_files=False, work_dir=working_directory.name, command_sock=command_sock, output_sock=output_sock):
	messages = []
	file_hashes = set()
	with tempfile.NamedTemporaryFile(dir=work_dir, suffix='.pcap') as f:
		f.write(pcap_file.read())
		#TODO: logging

		pcap_file_args = {'output-dir': os.path.join(work_dir, "logs"), 'filename': f.name}
		send_command(command_sock, 'pcap-file', pcap_file_args)

		#Poll the socket until it's done processing packets
		ret = send_command(command_sock, 'pcap-file-number')
		while ret['message'] > 0:
			time.sleep(0.1)
			ret = send_command(command_sock, 'pcap-file-number')

		try:
			while True:
				msg = receivemessage(output_sock)
				messages.append(msg)

				if 'event_type' in msg:
					if msg['event_type'] == 'fileinfo':
						#We need to keep track of extracted file paths so we can send them back later
						file_hashes.add(msg['fileinfo']['sha256'])
					elif msg['event_type'] == 'stats':
						#The "stats" message seems to be the last one
						# (which makes sense as the information contained is only available after the pcap is done being processed)
						break
		except socket.timeout:
			#Never even received a stats message
			pass

		if get_files:
			#Requested the files as well. We need to return a tar file containing all extracted files and a json file of metadata
			tar_file_obj = io.BytesIO()
			tar_file = tarfile.open(fileobj=tar_file_obj, mode='w')

			for file_hash in file_hashes:
				#Files are stored in a directory under <work_dir>/logs/files/<first 2 bytes of hash>/<hash>
				file_path = os.path.join(work_dir, 'logs', 'files', file_hash[0:2], file_hash)
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

			return tar_file_obj

	return messages
	

@application.route('/metadata', methods=['POST'])
def handle_metadata():
	alerts_and_metadata = process_pcap(request.files.get('pcap').stream, get_files=False)
	return json.dumps(alerts_and_metadata)

@application.route('/full', methods=['POST'])
def handle_full():
	metadata_and_files_tar = process_pcap(request.files.get('pcap').stream, get_files=True)
	return send_file(metadata_and_files_tar, attachment_filename="suricata_output.tar")

@application.route('/test', methods=['POST'])
def handle_test():
	#We have to spawn a new suricata instance in order to change the rule file that is being used
	# Which also means we have to set up a new logging directory and everything

	tmp_work_dir = tempfile.TemporaryDirectory(dir="/dev/shm/")
	os.mkdir(os.path.join(tmp_work_dir.name, "logs"))

	tmp_cmd_sock_path = os.path.join(tmp_work_dir.name, "suricata.sock")
	tmp_output_sock_path = os.path.join(tmp_work_dir.name, "logs", "eve.sock")

	rule_file_path = os.path.join(tmp_work_dir.name, "local.rules")

	print("Writing to {}".format(rule_file_path))
	print("Writing {}".format(request.form.get('rules')))
	with open(rule_file_path, 'w') as f:
		f.write(request.form.get("rules"))

	suricata_process = subprocess.Popen(['suricata', '-c', './config/suricata.yaml', '-S', rule_file_path, '--unix-socket={}'.format(tmp_cmd_sock_path)], stdout=subprocess.DEVNULL)

	#Create the socket that we'll read from and connect to it
	tmp_output_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	tmp_output_sock.bind(tmp_output_sock_path)
	tmp_output_sock.settimeout(10)

	#Wait for the suricata process to start up
	tmp_cmd_sock = None
	while tmp_cmd_sock is None:
		try:
			if stat.S_ISSOCK(os.stat(tmp_cmd_sock_path).st_mode):
				tmp_cmd_sock = socket.socket(socket.AF_UNIX)
				tmp_cmd_sock.connect(tmp_cmd_sock_path)
				tmp_cmd_sock.settimeout(10)
	
				#Apparently we have to send a version when we connect or suricata won't accept commands
				send(tmp_cmd_sock, {"version": '0.2'})
			else:
				raise FileNotFoundError()
		except FileNotFoundError:
			print("Waiting for {} to exist".format(tmp_cmd_sock_path))
			time.sleep(0.1)

	alerts_and_metadata = process_pcap(request.files.get("pcap").stream, get_files=False, work_dir=tmp_work_dir.name, command_sock=tmp_cmd_sock, output_sock=tmp_output_sock)
	send_command(tmp_cmd_sock, "shutdown")

	tmp_work_dir.cleanup()

	alerted = {}
	for record in alerts_and_metadata:
		if 'event_type' in record and record['event_type'] == 'alert' and 'alert' in record:
			if record['alert']['signature'] not in alerted:
				alerted[record['alert']['signature']] = 0

			alerted[record['alert']['signature']] += 1

	return json.dumps(alerted)

if __name__ == '__main__':
	application.run()
