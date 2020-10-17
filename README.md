# nanodnsd - NanoDNS dynamic DNS server.

![CMake](https://github.com/jkloetzke/nanodnsd/workflows/CMake/badge.svg)

You own a domain name with a root server and want to run your own dynamic DNS
service? Then this tiny DNS server might be what you are looking for. It
implements just the parts that are required for dynamic DNS and focuses on easy
configuration, standards compliance and security.

# Features

* DNS over UDP and TCP
* Dynamic update of A and AAAA records over HTTP
* HTTP update interface compatible with Fritz!BOX and others
* Future proof by implementing all recommended standards
  * See [DNS flag day](https://dnsflagday.net/) for more information
  * Tested with [ISC DNS compliance tests](https://gitlab.isc.org/isc-projects/DNS-Compliance-Testing)
  * Supports EDNS ([RFC6891](https://tools.ietf.org/html/rfc6891)) with DNS
    cookies ([RFC7873](https://tools.ietf.org/html/rfc7873))
* Hardened against DNS amplification attacks (rate limiting of UDP requests
  without DNS cookies) and "low and slow" attacks (drop slow clients,
  round-robin connection limit)
* Small footprint (<1 MB RAM, <100kB on disk)
* Optional systemd integration
  * Socket activation for fast system startup
  * Root-less operation because ports are bound by systemd
  * Uses `DynamicUser=true` to jail the service even more
* Drop root privileges when run without system

# Requirements

* OpenSSL >= 1.x.x
* Systemd (optional)

# Installation

    mkdir build
    cd build
    cmake ../src -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release
    make
    sudo make install

# Configuration

Copy the example configuration file `cfg/nanodnsd.conf` to `/etc` and adjust to
your configuration. On termination the current state of the daemon is saved to
`/var/lib/nanodnsd/nanodnsd.state`.

# Update API

Just do a HTTP GET or POST request with the following format:

    http://<server>/api/update?hostname=<host>&ipv4=1.2.3.4&ipv6=1:2::7:8&token=secret

The `hostname` and `token` parameters are mandatory. The `ipv4` and `ipv6`
parameters update the `A` and `AAAA` records in the DNS record of `hostname`.
If a IP parameter is missing the respective record is removed from the host.

`nanodnsd` does not support HTTPS. Use a reverse proxy to provide HTTPS instead.

# Example setup

In the example we assume that you own the domain `mydomain.test` and you would
like to let the dynamic host appear under the `dyn.mydomain.test` sub-domain,
e.g. `home.dyn.mydomain.test`. Additionally you have a server that has the IP
address `1.2.3.4` resp.  `11:22::33:44`.

## DNS zone setup

First of all you need a DNS provider that let's you define `NS` records in your
domain. Unfortunately this does not seem to be universally the case so make
sure you check your provider or move the domain to one that has support for
`NS` records. The `NS` record is required to delegate a subdomain to another
name server.

Give your server a public name so that it can be reached as DNS server. For
clarity we choose `ns.mydomain.test`. Hence define the following records in
your zone:

    Host    TTL     Class   Type    Address
    ----    ---     -----   ----    -------
    ns      86400   IN      A       1.2.3.4
    ns      86400   IN      AAAA    11:22::33::44

If your server has already a name there is nothing wrong with re-using it. But
having a dedicated name for the name server purpose makes a bit more clear.
Then define the `dyn` subdomain with a `NS` record pointing to the host name of
your server. This states that any host under `dyn.mydomain.test` is managed by
the `ns.mydomain.test` server.

    Host    TTL     Class   Type    Address
    ----    ---     -----   ----    -------
    dyn     86400   IN      NS      ns.mydomain.test

You *could* also announce your DNS server under the `dyn` subdomain, e.g.
`ns.dyn.mydomain.test`. This is not recommended because it will create a
circular lookup dependency. It is still possible but requires a static entry in
the DNS server for itself and the definition of glue records to your zone.

## Server configuration

On the server you have to install `nanodnsd` and copy the example configuration
file ([cfg/nanodnsd.conf](cfg/nanodnsd.conf)) to `/etc`. You will then have to
adapt it to your likening. The `[server]` section is the most important one
and you will have to set the `domain`, `nameserver` and `email` keys to your names.
The sample configuration names match this example.

    [server]
    domain=dyn.mydomain.test
    nameserver=ns.mydomain.test
    email=hostmaster@mydomain.test

You must have an email account that is actually capable of receiving mails at
the given address. It is recommended to keep the name `hostmaster` as most
people will assume that this is the account that manages the zone. Inside the
DNS `SOA` record some email address characters must be escaped. `nanodnsd` will
take care of that automatically.

Commented out values in the configuration file are default values.

Host names are statically defined in the configuration file. Sections for a
host start with `@` and the rest of the section name is the actual host name.
To update an entry dynamically you must define a `token`. This is an arbitrary
string and is used as authentication for the HTTP update request.

    [@home]
    token=somesecterpassphrase

By default the resource records of the host name will expire after one day.
Unless they are refreshed the resource records of the host name will be deleted
after one day. You can adjust the time with an `expire` entry. The default unit
is seconds but you can also specify minutes (`1m`), hours (`1h`) and days
(`1d`). Note that this is **not** the TTL of the resource record. The TTL is
currently hard coded to 60s in `defs.h`.

Entries without a token cannot be updated. Use them to define static entries in
the zone. You can define the `A` and `AAAA` records directly in the
configuration file:

    [@static]
    a=127.0.0.1
    aaaa=::1

## Fritz!BOX configuration

Go to the DynDNS tab in the Fritz!BOX admin interface and enter the following
settings (adapt to your domain names):

* DynDNS Provider: "User-defined"
* Update URL: `http://ns.mydomain.test/dns/api/update?hostname=<domain>&ipv4=<ipaddr>&ipv6=<ip6addr>&token=<pass>`
* User name: `-` (must be entered but is not used by `nanodnsd`)
* Password: `somesecterpassphrase`

Leave out the `&ipv6=<ip6addr>` part if your provider does not assign a
IPv6 address yet.
