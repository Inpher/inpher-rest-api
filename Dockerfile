# Pull base image
From tomcat:8-jre8

# Maintainer
MAINTAINER "betty <blagovesta@inpher.io">

# Copy to images tomcat path
ADD /target/ultraRest.war /usr/local/tomcat/webapps/