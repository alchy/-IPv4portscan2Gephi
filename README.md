# IPv4portscan2Gephi
simple TCP/CONNECT network scanner 

this network scanner script performs a simple TCP scan on networks listed in .xls file
and streams scan result to Gephi for real-time visualisation.

dependent on: https://github.com/totetmatt/GephiStreamer

1) data-reset.gephi file might be needed to load into Gephi before visualization
2) gephi has to have streaming plugin installed and enabled
3) Gephi must be configured to listen on hostname="localhost", port=8080, workspace="workspace0"
