# inpher-rest-api
RestAPI for Inpher _ultra. Its goal is to enable an easy developement of Web Applications that want to use Inpher _ultra.
More information on Inpher SDK _ultra here: https://inpher.io/mainproducts/#productdescription

## Setup
In order to setup a server that handles the API requests, Apache Tomcat 8.0.36 needs to be installed: http://tomcat.apache.org/download-80.cgi#8.0.36
There is a script to build and deploy the server on localhost. Just run
```
$ ./scripts/build-and-deploy.sh
```
Note that so far the script assumes that tomcat is installed in the $HOME folder.

## Documentation
A swagger documentation is available here: https://api.inpher.io/api/
