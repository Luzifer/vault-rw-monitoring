# Jimdo / vault-rw-monitoring

This tool is intended to monitor the availability of a Vault instance. It does not care about any HA setup, technical details like leader election or anything. It just does a write to the instance and tried to read back the string just written. If this fails a PagerDuty incident is opened to alert the owner of the instance.
