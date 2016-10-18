#!/bin/bash
OUT=""
OUT="$(echo "$OUT"; echo "<br>Stopping elastic: <br>"; docker stop elastic)"
OUT="$(echo "$OUT"; echo; docker rm -v elastic)"
OUT="$(echo "$OUT"; echo "<br>Stoppig zookeeper: <br>"; docker stop zookeeper)"
OUT="$(echo "$OUT"; echo; docker rm -v zookeeper)"
OUT="$(echo "$OUT"; echo "<br>Stopping rabbitMQ: <br>"; docker stop rabbitmq)"
OUT="$(echo "$OUT"; echo; docker rm -v rabbitmq)"
OUT="$(echo "$OUT"; echo "<br>Stopping HDFS: <br>"; docker stop hdfs)"
OUT="$(echo "$OUT"; echo; docker rm -v hdfs)"
OUT="$(echo "$OUT"; echo "<br>Restarting rabbitMQ: <br>"; docker run --name hdfs -d -t -p 9000:9000 -p 50070:50070 sequenceiq/hadoop-docker)"
OUT="$(echo "$OUT"; echo "<br>Restarting rabbitMQ: <br>"; docker run --name rabbitmq -td -p 5672:5672 rabbitmq)"
OUT="$(echo "$OUT"; echo "<br>Restarting elastic: <br>"; docker run --name elastic -td -p 9300:9300 -p 9200:9200 inpher/elastic-frequency:_ultra)"
OUT="$(echo "$OUT"; echo "<br>Restarting zookeeper: <br>"; docker run -td --name zookeeper -p 2181:2181 jplock/zookeeper)" 
OUT="$(echo "$OUT"; echo "<br>Restarting Tomcat: <br>")"
sleep 5
/home/ubuntu/projects/inpher-rest-api/scripts/restart-tomcat 

 echo "Content-type: text/html"
 echo ""
 echo "<h3>Cleanup completed</h3>"
 echo "<br><br>Log:<br> $OUT"
 echo "<br><br>"
