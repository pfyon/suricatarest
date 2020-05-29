# suricatarest
Suricata REST endpoint

POST a pcap to /full, /metadata, or /test to get the eve.json records in a list, a tar file containing the files and metadata.json, or a list of signatures that alerted on the pcap.

Example on how to get all of the metadata (no files):
```
curl -X POST --form pcap=@samples/anonymized.pcap 127.0.0.1:5000/metadata
```

Example on how to get all the metadata and the files in a tar file:
```
curl -X POST --form pcap=@samples/anonymized.pcap 127.0.0.1:5000/full
```

Example on how to run one or more rules against a pcap file:
```
curl -X POST --form pcap=@samples/anonymized.pcap --form 'rules="alert ip any any -> any any (msg:\"test\"; sid:1; rev:1;)"' 127.0.0.1:5000/test

...

{"test": 2}
```
