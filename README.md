Brassfork
=========

Reads pcap files, and spits out files for graphing with [Gephi](https://gephi.github.io/).

Usage
-----

```
go build brassfork
./brassfork -in=capture.pcap -edges=edges.csv -nodes=nodes.csv

```

You can import the edges and nodes from the csv files. Extra attributes generated for edges:

* Packages: Amount of packages related to edge
* SYNs: Detected SYN packages (attempted new connections)
* Bytes: Cumulative counter of bytes transported in IP frames

Example
-------

![Simple graph made with Gephi](example.png "Simple graph made with Gephi")
