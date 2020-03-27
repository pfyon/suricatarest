# suricatarest
Suricata REST endpoint

POST a pcap file to /suricata and get the records reported in eve.json in a list.

Example on how to use it:
```
curl -X POST --data-binary @samples/anonymized.pcap 127.0.0.1:5000/suricata
```
