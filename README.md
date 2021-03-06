# suricatarest

## Suricata REST endpoint

POST a pcap and/or set of rules to /full, /metadata, /test, or /validate. The pcap and/or rules will be processed by suricata. Optionally, include lua files for /test and /validate.

Note: Since suricata can run lua scripts that consist of arbitrary code, one should be careful how this service is exposed to untrusted users.

## Installation
- Install suricata as detailed in https://suricata.readthedocs.io/en/latest/install.html
  - Note: The default suricata config expects the rules used for /full and /metadata to be found at /var/lib/suricata/rules/suricata.rules.
  - Note: If you want lua support, make sure you build suricata with --enable-lua or --enable-luajit.
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
Expects a pcap file.

Returns all the same metadata as /metadata, as well as extracted files from the pcap as a single tar file.

Example:
```
curl -X POST --form pcap=@samples/anonymized.pcap 127.0.0.1:5000/full
```

### API /test
Expects a pcap file, one or more suricata rules in the same format as a .rules file, and optionally one or more lua files. Lua files are written alongside the rules file so should be referenced as such.

Returns a list of signatures that hit on the pcap file, and how many times each signature hit, as json.

Note: Does not provide feedback if a signature failed validation. I suggest hitting /validate first if you're concerned about your signatures being invalid.

Example:
```
curl -X POST --form pcap=@samples/anonymized.pcap --form 'rules="alert ip any any -> any any (msg:\"Test Signature\"; lua:1.lua; sid:1; rev:1;)"' --form 'lua[]=@samples/1.lua' 127.0.0.1:5000/test

...

{"Test Signature": 13}
```

### API /validate
Expects one or more suricata rules in the same format as a .rules file, and optionally one or more lua file. Lua files are written alongside the rules file so should be referenced as such.

Returns a list of errors while parsing the signature(s) as json. If there are any errors, an HTTP status code 406 NOT_ACCEPTABLE will be returned.

Currently, suricata does not seem to validate lua rule syntax.

Example:
```
curl -X POST --form 'rules="alert ip any any -> any any (msg:\"test\"; sid:notanumber; rev:1;)"' --form 'lua[]=@samples/1.lua' 127.0.0.1:5000/validate

...

["invalid character as arg to sid keyword", "error parsing signature \"alert ip any any -> any any (msg:\"test\"; sid:notanumber; rev:1;)\" from file /dev/shm/tmp4fciik6e/local.rules at line 1"]
``` 

