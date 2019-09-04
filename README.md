## OPNSenseTricks

Currently supports:
- Exporting configuration to a file.
- Uploading a new certificate for the web server.

#### Credentials
User credentials and server IP address are provided in a json file through
the `-c` switch E.G:  
```json
{
    "address" : "192.168.1.1",
    "username": "username",
    "password": "password"
}
```
`./opnsensetricks.rb -c /tmp/creds.json ...`
#### Changing the Webui's certificate.
In order to use the webui certificate replacement, we must install a php file to
OPNSense's web server.  
`/usr/local/www/install_cert.php` is supplied, simply drop it on the root
filesystem of your OPNSense install.

`-K` Path to the key file to use, File must be in PEM format.  
`-C` Path to the certificate file to use, File must be in PEM format.  
`-u` Finally, tell OPNSenseTricks you wish to update the certificate.  

Example: `./opnsensetricks.rb -c /tmp/creds.json -K /tmp/key.pem -C /tmp/cert.pem -u`

Optionally add `-v` for some verbose output. A log file will be generated
in the working directory OPNSenseTricks is run from, this file WILL contain
sensitive data.

#### Downloading config.
`-f` Specify the file to write the backup to.  
`-b` Finally, tell OPNSenseTricks you wish to download the config.  
Example: `./opnsensetricks.rb -c /tmp/creds.json -f /tmp/config.xml -b`


That's it! Enjoy using OPNSenseTricks, licensed MIT, but i really don't care,
do whatever, if you make cool modifications, please contribute. :D

~~I was learning ruby when i wrote this, its probably horrible xD~~
