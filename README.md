# nanodnsd
NanoDNS dynamic DNS server

This is a tiny DNS server that is meant to be used for dynamic DNS setups.

# Installation

    mkdir build
    cd build
    cmake ../src -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release
    make
    sudo make install

# Configuration

Copy the example configuration file `cfg/nanodnsd.conf` to `/etc` and adjust to
your configuration.

# Update API

Just do a HTTP GET or POST request with the following format:

    http://<server>/api/update?hostname=<host>&ipv4=1.2.3.4&ipv6=1:2::7:8&token=secret

The `hostname` and `token` parameters are mandatory. The `ipv4` and `ipv6`
parameters update the `A` and `AAAA` records in the DNS record of `hostname`.
If a IP parameter is missing the respective record is removed from the RR.
