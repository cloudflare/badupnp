badupnp
===

This is a simple web service that tests if the viewer is running a
router that is responding to UPnP / SSDP on the internet. This is
bad because UPnP returns many more packets than the requesting system
sends it, combined with UDP as a transport, it makes it a protocol ripe
for abuse for DDoS reflection.

example systemd units:

```
[Service]
ExecStart=/usr/bin/badupnp
Restart=always
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=badupnp
User=root
WorkingDirectory=/usr/local/badupnp/
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

Example lighttpd reverse proxy info:

```
# ensure you have mod_proxy loaded

$HTTP["host"] == "badupnp.benjojo.co.uk" {
    proxy.server  = ( "" => ( (
            "host" => "127.0.0.1",
            "port" => 753
    ) ) )
}
```
