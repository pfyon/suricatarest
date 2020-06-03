# suricatarest

## Suricata REST endpoint

POST a pcap and/or set of rules to /full, /metadata, /test, or /validate. The pcap and/or rules will be processed by suricata.

## Installation

- Install suricata as detailed in https://suricata.readthedocs.io/en/latest/install.html
- Clone repository
```
git clone https://github.com/pfyon/suricatarest.git
```
- Install dependencies
```
pip install -r suricatarest/requirements.txt
```
- Run out of the cloned source directory
```
cd suricatarest/
./run.sh
```

### API /metadata
Expects a pcap file.
Returns all metadata (alerts and extracted fields) as json.

Example:
```
curl -X POST --form pcap=@samples/anonymized.pcap 127.0.0.1:5000/metadata
```

### API /full
Expects a pcap file
Returns all the same metadata as /metadata, as well as extracted files from the pcap as a single tar file.

Example:
```
curl -X POST --form pcap=@samples/anonymized.pcap 127.0.0.1:5000/full
```

### API /test
Expects a pcap file and one or more suricata rule in the same format as in a .rules file.
Returns a list of signatures that hit on the pcap file, and how many times each signature hit, as json.
Note: Does not provide feedback if a signature failed validation. I suggest hitting /validate first if you're concerned about your signatures being invalid.

Example:
```
curl -X POST --form pcap=@samples/anonymized.pcap --form 'rules="alert ip any any -> any any (msg:\"test\"; sid:1; rev:1;)"' 127.0.0.1:5000/test

...

{"test": 2}
```

### API /validate
Expects one or more suricata rules in the same format as in a .rules file.
Returns a list of errors while parsing the signature(s) as json. If there are any errors, an HTTP status code 406 NOT_ACCEPTABLE will be returned.

Example:
```
curl -X POST --form 'rules="alert ip any any -> any any (msg:\"test\"; sid:notanumber; rev:1;)"' 127.0.0.1:5000/validate

...

["invalid character as arg to sid keyword", "error parsing signature \"alert ip any any -> any any (msg:\"test\"; sid:notanumber; rev:1;)\" from file /dev/shm/tmp4fciik6e/local.rules at line 1"]
``` 

