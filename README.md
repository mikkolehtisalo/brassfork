Brassfork
=========

Reads pcap files, and spits out files for graphing with [Gephi](https://gephi.github.io/).

Usage
-----

```
go build brassfork
./brassfork -in=capture.pcap -edges=edges.csv -nodes=nodes.csv
```

You can import the edges and nodes from the csv files. 

Attributes
----------

Extra attributes generated for edges:

* Packages: Amount of packages related to edge
* SYNs: Detected SYN packages (attempted new TCP connections)
* Bytes: Cumulative counter of bytes transported in IP frames. This is also set as the weight for edges.

Extra attributes generated for nodes:

* Network: Name of the network, based on CIDR network mask (see below)

Network names
-------------

Network names are useful for partitioning data in Gephi. Create a valid JSON file containing information about your known networks. Take a look at *example.json*:

```json
[
  {
    "CIDR": "192.168.1.0/24",
    "Name": "Home network"
  },
  {
    "CIDR": "192.168.2.0/24",
    "Name": "Other network"
  }
]
```

After creating the file run brassfork with the -networks parameter, like

```
./brassfork -in=capture.pcap -edges=edges.csv -nodes=nodes.csv -networks=example.json
```

The nodes output should contain the Network information for nodes with matching IP addresses.

Example
-------

![Simple graph made with Gephi](example.png "Simple graph made with Gephi")
