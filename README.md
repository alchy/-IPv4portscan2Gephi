# IPv4portscan2Gephi
simple TCP/CONNECT network scanner 
----------------------------------

This network scanner script performs a simple TCP-CONNECT scan on networks listed in .xls file
and streams scan result to Gephi for real-time visualisation.

dependent on: https://github.com/totetmatt/gephiStreamer

1) data-reset.gephi file might be needed to load into Gephi to make sure you can see the visualization
2) Gephi has to have streaming plugin installed and enabled
3) Gephi streaming plugin must be configured to listen on hostname="localhost", port=8080, workspace="workspace0"
