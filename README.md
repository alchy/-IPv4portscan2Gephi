# IPv4portscan2Gephi
simple TCP/CONNECT network scanner
----------------------------------

This network scanner script performs a simple TCP-CONNECT scan on networks listed in .xls file
and streams results to Gephi for real-time network visualisation.

What is Gephi?
Gephi is the leading visualization and exploration software for all kinds of graphs and networks.
Gephi is open-source and you may get it @ https://gephi.org/

The scripts requires 'gephistreamer': https://github.com/totetmatt/gephiStreamer

HOW-TO
1) load data-reset.gephi file to Gephi before streaming graph (workaround for some glitch in Gephi when the graph hodes and edges are not visible)
2) Gephi has to have streaming plugin installed and enabled
3) Gephi streaming plugin must be configured to listen on hostname="localhost", port=8080, workspace="workspace0"
