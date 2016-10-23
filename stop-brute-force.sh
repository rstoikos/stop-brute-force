#########################################################################################################
# This basic bash script uses two functions that return the ip address of the user that tried to access #
# wp.login.php and xmlrpc.php more than 15 times, by simply checking 'apachectl fullstatus'.            #
# Afterward the IP address of the attacker is passed to IP tables and a new rule is added.              #
#########################################################################################################

#!/bin/sh


return_attackerIP_for_wplogin () {	

apachectl  fullstatus | grep -i "wp-login.php" | awk '{print $11}' | sort | uniq -c | awk '{  if ( $1 > "15")   print $2 }'

}


return_attackerIP_for_xmlrpc () {

apachectl  fullstatus | grep -i "xmlrpc.php" | awk '{print $11}' | sort | uniq -c | awk '{  if ( $1 > "15")   print $2 }'

}

while true ; do
    
  for ip in $( return_attackerIP_for_wplogin ) ; do      # for every ip that tried to access login.php more than 15 times
  
        iptables -C INPUT  -s $ip -m state --state ESTABLISHED,RELATED,NEW     -p tcp --destination-port 80 -j DROP 
        # -C = checks if rules is already there or else we will flood the ip tables with same rules

        RESULT=$?            
           if   [ $RESULT -eq 1 ] ; then    # if rule is not there , then add it
                    
                iptables -A INPUT  -s $ip -m state --state ESTABLISHED,RELATED,NEW -p tcp --destination-port 80 -j DROP
                echo "rule added for ip address :  $ip " >> /tmp/stop_brute_force.log

           fi     
                      
         done

	#########################################################################################################
	# Do it again for the xmlrpc.php                                                                        #
	#########################################################################################################

for ip in $( return_attackerIP_for_xmlrpc ) ; do      # for every ip that tried to access to xmlrpc.php more than 15 times 
  
        iptables -C INPUT  -s $ip -m state --state ESTABLISHED,RELATED,NEW     -p tcp --destination-port 80 -j DROP 
        # -C = checks if rules is already there or else we will flood the ip tables with same rules

        RESULT=$?            
           if   [ $RESULT -eq 1 ] ; then    # if rule is not there , then add it

                iptables -A INPUT  -s $ip -m state --state ESTABLISHED,RELATED,NEW -p tcp --destination-port 80 -j DROP
                echo "rule added for ip address :  $ip " >> /tmp/stop_brute_force.log               

           fi     

         done

sleep 60

done
