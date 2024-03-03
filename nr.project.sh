#!/bin/bash

								#####################################################################################################################################
								# Script Name: nr.project.sh																										#
								# Description: The goal of the script is to create a system for reconnaissance purposes in which the controller manages the agent   #
								# 			   automatically and send him instructions to scan sources for the Master which is performed automatically				#
								# 			   and transfer the information of the scans automatically.																#
								# 			   - Controller (Master)																								#
								#			   - Server (Agent)																										#
								# Author: Adir Salinas (code S18)																									#
								# Date: 14.01.2024																					   			                    #
								# Class code: 7736																				                     				#
								# Lecturer: Natali Erez																												#
								#####################################################################################################################################
 			           



# Functions names and short description:
# 1) Functions for update the system to make sure we have the needed links and recent packages: UPDATE 
# 2) Functions for installing applications : NMAP, GEO, SSHPASS, WHOISAPP, NIPE.
# 3) Functions that display text animation for installing the application : INSTALL
# 4) Functions to check if the application is installed: NMAPINFO, GEOINFO, SSHPASSINFO, WHOISINSTAL, NIPEINFO.
# 5) Functions to verify whether your network connection is anonymous : ANON , ANONCNRY
# 6) Functions to check anonymity and if nipe is not running: FALSE-(restarting the nipe to start it) TRUE-(verify the user country does not match the nipe country).
# 7) Functions to extract the information about the attempts to connect to the server: LOG-(commands to check if the connection was successful) SCANLOG-(the output to the file according to the LOG function).
# 8) Functions to create a file for the different scans output that was executed: NMAPSCAN-(nmap scan for the domain) WHOIS-(whois scan for the domain).
# 9) Function that allows the user to enter details of the ssh server, after that checks that the details are correct and displays information about the ssh server: VPS
#10) Function that allows the user to enter a Domain/ip , after that run checks that the Domain/ip are correct and displays information about the Domain/ip: DMN
#11) Function that finish the script and display text where the log and scans file are locate and case options to display them on screen: END 


# Descriptions About A Few Commands In The Script:
#-------------------------------------------------
# "echo" - Making space between commands or displaying text on screen.
# "clear" - clearing the output terminal screen.
# "sleep" - this command used to introduce a delay or pause in the script for a certain period of time.
# "cd" - Short for "change directory," is used in the script and allows you to navigate between directories and move to a different location.
# "grep" - searching for word or sentence inside an output and display them on screen.
# "awk" - have a lot of used most of them in the script is to separate certain words or location.
# "read" - read command reads the user's input and assigns it to the variable, using the flag (-p) after the command for printing text on screen before the input. 
# "nmap" - is an open-source network scanning tool used for discovering devices, services, and vulnerabilities on computer networks.
# "whois" - tool that provides information and details about a domain names, including details about the domain's owner, registrar, and registration dates.
# “sudo” - command is used to execute commands with elevated privileges. and it allows a permitted user to execute a command as the superuser.
# "sudo apt-get install" - command to install diffrent packages or applications.
# "> /dev/null 2>&1" - this command used in addition to another command to executed it quietly without displaying any output or errors.
 
clear  
echo "[!] You may need to enter a password for the script:"  
echo 
sleep 1.5
sudo apt-get install -y figlet > /dev/null 2>&1 # command to install the 'figlet' package, that generates ASCII art text banners using various font styles. the flag -y is for automatically answer "yes" for questions.  for visual purpose only.

function START () # Function for the start of the script and display short description about the purpose of the script and few details. 
{
	clear
	figlet -t -c -f standard "Welcome To My Sciprt !" # this command convert text to ascii(more artistic way),"-t" for expanding to the entire screen,"-c" for centering the text, and "-f" for specify which font to use in this case its "standard font".
	sleep 3
	echo 
	echo
	echo " The Purpose Of The Script Is To Scan Different Domains And IP Addresses While Being Completely Anonymous And Collect Data Scans To Your Computer Safely. "
	sleep 8
	echo
	echo " It will be performed as following: "
	echo
	sleep 2
	echo " - Controller "
	sleep 1
	echo " - Agent"
	echo
	sleep 2
	echo "        You Will Be Operated As The Controller, Firstly You Gonna Perform Remote Control On Your Agent After We Make Sure You Completely Anonymous. "
	sleep 7.5
	echo
	echo "                 Then You Will Send Commands To The Agent That Will Performed Several Scans For Domains Or IP Addresses That You Wanted.  "
	sleep 7
	echo
	echo "                        And Finally Will Transfer All The Scan Data To A File On Your Computer In The Most Safest Way Possible. "
	sleep 6
	echo
	echo "                                                                    So Lets Start..."	
	sleep 2.5
}
START

function UPDATE () # Function is to updating the system in order to make sure to have the recent packages and links of the applications.
{
	echo
	echo
	echo
	echo "[*] Before We Start Please Wait While We Updating Your System...  " 
	sleep 1
	echo "                (It may take a few minutes) " 
	sleep 1.5
	echo
	echo
	sudo apt update -y &>/dev/null # commmand to update your system
	echo
	echo
	echo "[+] Your System Has Been Updated Successfully."
	echo
	sleep 2
	echo "[?] Progressing To Check If The Necessary Applications Are Installed. "
	echo
	echo
	sleep 2
}
UPDATE
#************************************************************#

# Installing small needed applications:

sudo apt-get install -y lolcat > /dev/null 2>&1  # installing the application lolcat that outputs text with rainbow-colored letters and changing the color of the text, for visual purpose only.
sudo apt-get install -y cmatrix > /dev/null 2>&1 # installing the application cmatrix that creating a visually dynamic and animated display of characters on the terminal screen. for visual purpose only.

# The following functions is for downloading the necessary applications if they are not installed. 

function NMAP () # Script to download nmap.
{
	sudo apt-get -qq -y install nmap 1> /dev/null  # apt-get -y said say "yes" to all questions, and "-qq" means "do things quietly" suppresses most of the output.
}	
#NMAP


function GEO () # Script to download Geoiplookup.
{
	sudo apt-get -qq -y install geoip-bin 1> /dev/null # apt-get -y said say "yes" to all questions, and "-qq" means "do things quietly" suppresses most of the output.
}	
#GEO

function SSHPASS () # Script to download Sshpass.
{
	sudo apt-get install -y sshpass > /dev/null 2>&1 # apt-get -y said say "yes" to all questions.
}	
#SSHPASS

function WHOISAPP () # Script to download whois.
{
	sudo apt-get -qq -y install whois 1> /dev/null  # apt-get -y said say "yes" to all questions, and "-qq" means "do things quietly" suppresses most of the output.
}	
#WHOISAPP

function NIPE () # Script to download Nipe.
{
	cd ~ > /dev/null 2>&1  # Navigate back to the home directory to make sure Nipe is installed there.
	git clone https://github.com/GouveaHeitor/nipe > /dev/null 2>&1 && cd nipe # Git clone command will download the entire content of the URL given and create a copy directory named "nipe", then entering the directory. 
	sudo apt-get install -y cpanminus > /dev/null 2>&1  # installing "cpanminus" package allowing you to easily manage Perl modules.
	sudo cpanm install Switch JSON LWP::UserAgent Config::Simple > /dev/null 2>&1 # "cpanm" is used to install Perl modules, and "Switch JSON LWP::UserAgent Config::Simple" are the name of the perl modules.
	sudo perl nipe.pl install > /dev/null 2>&1 # "perl" is used to run Perl scripts, and then specify the name of the script "nipe.pl".
	sudo perl nipe.pl start > /dev/null 2>&1 # and then specify the word start for the script "nipe.pl to executed the according commands in the script to start Nipe. 
}
#NIPE


#************************************************************#

function INSTALL () # Function to show animated text, that getting called when installing an application or package.
{
		echo
		echo "[!] Your Application Is Not Installed, Progressing To Download... "
		echo
		sleep 1.5
		echo "[*] Continuing To Install The Application."
		sleep 3
		clear 
		echo "> Installing the application. "
		sleep 0.5
		clear 
		echo "> Installing the application.. "
		sleep 0.5
		clear
		echo "> Installing the application... "
		sleep 0.5
		clear
		echo "> Installing the application. "
		sleep 0.5
		clear
		echo "> Installing the application.. "
		sleep 0.5
		clear
		echo "> Installing the application... "
		sleep 2 
}	

#************************************************************#

function NMAPINFO () # Function to check if Nmap application is installed.
{
	if [ -f /usr/bin/nmap ] # For the following syntax: "-f" is used to check if the file exist in the following path. if its exist went to "then", if not existing went to "else".
	then 
		echo "[?] Checking If NMAP Is Already Installed... "
		sleep 3
		echo
		echo "[*] The Application Is Installed."
		sleep 2
	else 
		clear
		echo "[?] Checking If NMAP Is Already Installed... "
		sleep 3
		echo
		INSTALL	
		echo		
		NMAP
		clear
		echo "[+] The Appliction Has Been Successfully Downloaded!"
		sleep 2
	fi	
}
NMAPINFO

#.......................................................................................

function GEOINFO () # Function to check if Geoiplookup application is installed.
{
	if [  -f /usr/bin/geoiplookup ]  # For the following syntax: "-f" is used to check if the file exist in the following path. if its exist went to "then", if not existing went to "else".
	then
		echo
		echo
		echo "[?] Checking If GeoIpLookup Is Already Installed... "
		sleep 3
		echo
		echo "[*] The Application Is Installed."
		sleep 2
	else 
		echo
		echo
		echo "[?] Checking If GeoIpLookup Is Already Installed... "
		sleep 3
		echo
		INSTALL
		echo
		GEO
		clear
		echo "[+] The Appliction Has Been Successfully Downloaded!"
		sleep 2
	fi	
}
GEOINFO

#...................................................................................

function SSHPASSINFO () # Function to check if Sshpass application is installed.
{
	if [ -f /usr/bin/sshpass ] # For the following syntax: "-f" is used to check if the file exist in the following path. if its exist went to "then", if not existing went to "else".
		then
		echo
		echo
		echo "[?] Checking If SshPass Is Already Installed... "
		sleep 3
		echo
		echo "[*] The Application Is Installed."
		sleep 2
	else 
		echo
		echo
		echo "[?] Checking If SshPass Is Already Installed... "
		sleep 3
		echo
		INSTALL
		echo
		SSHPASS
		clear
		echo "[+] The Appliction Has Been Successfully Downloaded!"
		sleep 2
	fi	
}	
SSHPASSINFO

#.................................................................................

function WHOISINSTAL () # Function to check if whois application is installed.
{
	if [ -f /usr/bin/whois ] # For the following syntax: "-f" is used to check if the file exist in the following path. if its exist went to "then", if not existing went to "else".
		then
		echo
		echo
		echo "[?] Checking If Whois Is Already Installed... "
		sleep 3
		echo
		echo "[*] The Application Is Installed."
		sleep 2
	else 
		echo
		echo
		echo "[?] Checking If Whois Is Already Installed... "
		sleep 3
		echo
		INSTALL
		echo
		WHOISAPP
		clear
		echo "[+] The Appliction Has Been Successfully Downloaded!"
		sleep 2
	fi	
}	
WHOISINSTAL

#...............................................................................

function NIPEINFO () # Function to check if Nipe application is installed.
{
	cd ~ && cd nipe > /dev/null 2>&1 # Change the location to home directory and then entering nipe directory.
	path=$(pwd)  # executing 'pwd' command (outputs the current directory path) and insert it into a variable named "path".
	NIPEPATH=$path/nipe.pl  # adding "nipe.pl" to the "pwd" command to make a full path to the nipe.pl file, and insert it into a variable named "NIPEPATH".
	if [ -f $NIPEPATH ]  # For the following syntax: "-f" is used to check if the file exist in the following path. if its exist went to "then", if not existing went to "else".
	then
		echo
		echo
		echo "[?] Checking If NIPE Is Already Installed... "
		sleep 3
		echo
		echo "[*] The Application Is Installed."
		sleep 2
	else 
		echo
		echo
		echo "[?] Checking If NIPE Is Already Installed... "
		sleep 3
		echo	
		INSTALL # calling the function called INSTALL and executes the code inside the function.
		NIPE # calling the function called NIPE and executes the code inside the function.
		clear
		echo "[+] The Appliction Has Been Successfully Downloaded!"
		sleep 2
	fi
	
}
NIPEINFO

#*******************************************************************************#
	
function TRUE () # Function to check if the network connection is anonymous and ask the user to type his country.
{
	clear
	echo
	echo "[*] To Perform Remote Control And Scaning Other Domains, You Need To Be Anonymous."
	sleep 3
	echo
	echo "[?] Checking If Your Network Connection Is Anonymous... "
	sleep 2
	# IP Address:
	IPNIPE=$(sudo perl nipe.pl status | grep Ip | awk '{print $3}') # getting status from Nipe about the spoof IP, grep command to grep Ip row and awk the ip address, and insert it into a variable named "IPNIPE".
	# Country name:
	NIPECOUNTRY=$(geoiplookup $IPNIPE |awk '{print $5}'|tr '[:upper:]' '[:lower:]') # using geoiplookup on the variable "IPNIPE", using awk to separate the spoof country, using 'tr' command to make the country in lower case only, and insert it into a variable named "NIPECOUNTRY".
	echo
	echo
	sleep 1
	echo "[*] To display If You Are Anonymous Please Insert Your Country. "
	sleep 1
	echo
	read -p " >  Write Your Country In Lower Case Only! : " USERCOUNTRY # read command used to read the input word the user typing, and insert it into a variable named "USERCOUNTRY", flag -p used for printing text on screen before the input. 
}	
#TRUE	
#...................................................................................................

function FALSE () # Function to restarting and starting the Nipe application, in case the nipe didnt work and didn't displayed the new spoof IP.
{
	sudo perl nipe.pl restart # inserting "restart" variable inside the nipe.pl script that executed the commands inside the script to restart the Nipe application
	sudo perl nipe.pl start # inserting "start" variable inside the nipe.pl script that executed the commands inside the script to start the Nipe application
	sudo perl nipe.pl status # inserting "status" variable inside the nipe.pl script that executed the commands inside the script to display the IP status.
}
#FALSE	
#...................................................................................................

function ANON() # Function to check whether the status of the Nipe is working and change the ip address, if not call the function to restart Nipe in order to be anonymous.
{
	cd ~ && cd nipe > /dev/null 2>&1  # Change the location to home directory and then entering nipe directory.
	sudo perl nipe.pl stop > /dev/null 2>&1  # inserting "stop" variable inside the nipe.pl script that executed the commands inside the script to stop the Nipe application
	sudo perl nipe.pl restart > /dev/null 2>&1  # inserting "restart" variable inside the nipe.pl script that executed the commands inside the script to restart the Nipe application
	sudo perl nipe.pl start > /dev/null 2>&1  # inserting "start" variable inside the nipe.pl script that executed the commands inside the script to start the Nipe application	
	echo
		
	ifon=$(sudo perl nipe.pl status | grep -io true|tr '[:upper:]' '[:lower:]')  # getting the status output of Nipe, grep the word "true" and using 'tr' command to make true word lower case only, and insert it into a variable named "ifon".
	ifoff=$(sudo perl nipe.pl status | grep -io false|tr '[:upper:]' '[:lower:]') # getting the status output of Nipe, grep the word "false" and using 'tr' command to make false word lower case only, and insert it into a variable named "ifoff".
	
	if [ $ifon = "true" ] # For the following syntax: if the variable "ifon" equal to "true" continue to "then" statement .
	then
		TRUE  # calling the Function called TRUE
	elif [ $ifoff = "false" ] # the 'elif' statment is alternative action if the previous conditions are not met. if the variable "ifoff" equal to "false" so continue to "then" statement.
	then
		FALSE  # calling the Function called FALSE
		TRUE  # calling the Function called TRUE
	fi			
}
ANON
#....................................................................................................................

function ANONCNTRY () # Function to check if network connection is anonymous if it is display details about the new spoof ip and country, and if not restarting Nipe to make connection anonymous.
{                                      
	if [ $NIPECOUNTRY = $USERCOUNTRY ] # The If statement said that if NIPECOUNTRY variable equal to the USERCOUNTRY variable, means t if the country the user input is different then the Nipe spoof country the connection is anonymous and can move to 'else' statement. if they are equal, restart Nipe by moving to 'then' statement.
	then
		sleep 2
		clear
		echo "[?] Checking If Your Network Connection Is Anonymous... "
		sleep 3
		echo "[*] Your Network Connection Is Not Anonymity! "
		sleep 2
		echo "[-] Progressing To Try Again To Make You Anonymous..."
		sleep 4
		ANON  # Calling ANON function for restarting Nipe in order to make connection anonymous
		ANONCNTRY  # Calling ANONCNTRY again to check if both of the country is equal that verify anonymity.
	else
		sleep 3
		clear
		echo "[!] Your Network Connection Is Completely Anonymous And Safe To Continue. "
		echo 
		sleep 3
		echo " > Your New Spoofed Country name: $NIPECOUNTRY"
		sleep 1
		echo
		echo " > Your New Spoofed IP Address: $IPNIPE"
		echo
		sleep 2.5
		echo "[*] Connecting To A Remote Server ... "
		sleep 3
		echo
	fi
}
ANONCNTRY

function LOG () # Function to create a log file stracture and extracting all the needed details through the ssh connection to make the the log file. (this function being called after the user enter the ssh server details).
{
	
	function ACCFAIL () # This Function will try to connect to an ssh server according to the details given by the user, if the connection was successful or not, the event will be displayed in the logfile.
	{
    sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP exit # "sshpass" used for entering ssh server password (-p flag used to enter single password, -P flag used to enter passwords file), "-o StrictHostKeyChecking=no" This option disables strict host key checking. "exit" for immediately exits the session after ssh server was checked. 

    if [ $? -eq 0 ]; # is a conditional expression that checks whether the last command was successful. "$?"- holds the exit status of the last executed command. A value of 0 usually means success. so if its equal to 0 then continue to 'then' statment if not so continue to 'else' statment.
    then
        echo "Accepted Password"
    else
        echo "Failed Password"
    fi
	}
	
accfail=$(ACCFAIL) # getting the output of the echo of ACCFAIL function and insert it into a variable named "accfail".

# Display The list all processes that run on the device and cut the number of PID of sshd and display on screen to add inside the logfile	
pid=$(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USR@$IP" 'ps -e | grep -i sshd | head -n1' 2>/dev/null | awk '{print $1}') # after the command being executed inserting the PID output of the ssh connection into a variable named "pid".

if [ -z "$pid" ];  # The flag -z is to check if "pid" variable is empty if so move to 'then' statment and print Unknown when using the 'pid' variable in the log file.
then
    pid="Unknown"
fi

# "netstat" command is used to provides information about network connections, routing tables, interface statistics and more.
# Send netstat command to the device to display all the ESTABLISHED connections (netstat -t flag display information about TCP connections) then grep for ssh and using awk to cut the random port of the connection to put in the logfile.
portnum=$(sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "netstat -t |grep -i ESTABLISHED|grep -i ssh") # after execute the command the all row of the random port is displayed, inserting it into a variable named "portnum"
PORTNUM=$(echo "$portnum" |awk '{print $5}'|awk -F: '{print $2}') # echo the variable "portnum" that contain the all row of the random port after that 'awk' for the port number and using awk to grep the port number only without the ":" symbol. and insert it into a variable named "PORTNUM". 

# The command (date +'%b %e %H:%M:%S') will say what to display while using 'date' (%b-format represents month name)(%e-format represents day)(%H-format represents hour)(%M-format represents minute)(%S-format represents second).
cd ~ && cd Desktop # Change the location to home directory and then entering Desktop directory.
mkdir Project.files > /dev/null 2>&1 # ("mkdir" command used for creating directories) making new directory inside Desktop named "Project.files"  
cd ~ && cd Desktop && cd Project.files # Change the location to home directory and then entering Desktop directory and entering the new created directory named "Project.files".
echo "$(date +'%b %e  %H:%M:%S') sshd[$pid]: $accfail for $USR from $IPNIPE port $PORTNUM ssh2." >> NR.log # making the stracture of the log file and using all the nessessory variables that was created before and using the ">>" to insert it into a new file named "NR.log"

	function SCANLOG () # Function for making a structure of the log file the scaning domains and collecting data while using all the nessessory variables inside the log. (the ">>" command used to adding text to a file without without overwriting its existing contents.)
	{
		cd ~ && cd Desktop && cd Project.files # Change the location to home directory and then entering Desktop then entering the directory named "Project.files".
		echo "$(date +'%b %e  %H:%M:%S') sshd[$pid]: $IPNIPE port $PORTNUM scan $DMN using Nmap successfully." >> NR.log
		echo "$(date +'%b %e  %H:%M:%S') sshd[$pid]: Nmap data scan collected successfully inside $IPNIPE for: $DMN" >> NR.log
		echo "$(date +'%b %e  %H:%M:%S') sshd[$pid]: $IPNIPE port $PORTNUM scan $DMN using Whois successfully." >> NR.log
		echo "$(date +'%b %e  %H:%M:%S') sshd[$pid]: Whois data scan collected successfully inside $IPNIPE for: $DMN" >> NR.log
	} 
}	
function NMAPSCAN () # Function for scanning using nmap the user chosen country and creating a file named "Nmap.scan" and send all details of the nmap scan to the new file. (the ">>" command used to adding text to a file without overwriting its existing contents.)
{
	cd ~ && cd Desktop && cd Project.files  # Change the location to home directory and then entering Desktop directory and entering the "Project.files" directory. 
	echo " "
	echo "[+] Result Of Nmap Scan For: $DMN" >> Nmap.scan
	echo " " >> Nmap.scan
	sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "nmap -p 22,21,80,443,25,3389,53 --open $DMN -Pn" >> Nmap.scan # scanning the user chosen country (using -p to specify port number) scan for the 7 most known, when using "--open" its displaying only the open ports, and using "-Pn" to Skip host discovery and assumes that the target are online.
	echo " " >> Nmap.scan
	echo "***********************************************************" >> Nmap.scan
} 

function WHOIS ()  # Function for scanning using whois the user chosen country and creating a file named "Whois.scan"  and send all details of the nmap scan to the new file. (the ">>" command used to adding text to a file without overwriting its existing contents.)
{
	cd ~ && cd Desktop && cd Project.files  # Change the location to home directory and then entering Desktop directory and entering the "Project.files" directory. 
	echo " " >> Whois.scan
	echo "[+] Result Of Whois Scan For: $DMN" >> Whois.scan
	echo " " >> Whois.scan
	sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "whois $DMN" >> Whois.scan  # scanning using whois command the user chosen country.
	echo " " >> Whois.scan
	echo "***********************************************************" >> Whois.scan
} 

function VPS() # This Function Will ask the user for the ssh server details. then creating a loop to check if the details are correct if not ask the user again for correct details, if the details are correct exit the loop and continue to display information about the ssh server.

{
	echo "[*] To Preform Remote Control, You Will Need To Fill In The Following Details... "
	echo
	sleep 3
	# Creating a loop that ask the user for ssh server details then trying to connect until a successful SSH connection is established, in case is not going to the start of the loop and ask for details again.
	while true
	do
		read -p " > Please Enter The IP Address Of The SSH Server: " IP  # reading the user input and asking him for the ip address of the ssh server, insert it into a variable named "IP".
		echo
		sleep 1
		read -p " > Please Enter The Username Of The SSH Server: " USR   # reading the user input and asking him for the username of the ssh server, insert it into a variable named "USR".
		echo
		sleep 1
		read -p " > Please Enter The Password Of The SSH Server: " PASS  # reading the user input and asking him for the password of the ssh server, insert it into a variable named "PASS".
		echo
		echo
		sleep 1
		echo "[?] Please Wait While We Verify The Details Are Correct..."
		echo "              (Might take some time)"
		echo
		echo
		
		# command to attempt to connect to the ssh server using the credentials the user provided.
		sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -v "$USR"@"$IP" exit > /dev/null 2>&1 # "sshpass" used for entering ssh server password, "-o StrictHostKeyChecking=no" This option disables strict host key checking. "-v" flag enables verbose mode, providing more detailed information. "exit" for immediately exits the session after ssh server was checked. 	
	    
	    if [ $? -eq 0 ]; # is a conditional expression that checks whether the last command was successful. "$?"- holds the exit status of the last executed command. A value of 0 usually means success. so if its equal to 0 then continue to 'then' statment if not so continue to 'else' statment.
	    then 
			LOG  # calling the LOG function to write the event into the log file
			break #  The break command is used to break out of the loop when the statemant are currect.
		else
			echo
			LOG > /dev/null 2>&1  # calling the LOG function to write the event into the log file
			echo "[!] One Of The Following Details Are Incorrect. Please try again."
			sleep 5
			clear			
		fi
	done  # end of the loop.
	sleep 3
	echo "[!] Your Details Are Correct. Progressing... "
	sleep 2
	echo
	echo
	echo "[*] Scaning The Device Of The SSH Server..."
	sleep 2.5
	echo
	TIME=$(sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP uptime) # connecting via ssh to the server using the credentials the user provided and send the command "uptime" ("uptime"-how long a system has been running and its current load). and inserting it into a variable named "TIME".
	DVCIP=$(sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP 'hostname -I') # connecting via ssh to the server using the credentials the user provided and send the command "hostname -I" ("hostname -I"- Display the ip of the device). and inserting it into a variable named "DVCIP".
	DVCNTRY=$(sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "geoiplookup \$(curl -s ifconfig.co) | awk '{print \$5}'") # connect to the ssh server runing command "curl -s ifconfig.co" that reveal the external ip address, using "geoiplookup" command on the external ip to reveal the country, and using 'awk' to separate the country name only and inserting it into a variable named "DVCNTRY".
	echo " > The IP Address Of The Device: $DVCIP "
	echo
	sleep 2
	echo " > The Country Associated To The Device: $DVCNTRY"
	echo
	sleep 2
	echo " > Uptime Of The Device: $TIME" 
	echo
	sleep 2	
	echo "[!] The Scan Results Of The Device Are Over. "
	echo
	echo
	sleep 3

}	
VPS

function FUNDMN () # Function that create a loop to ask the user for Domain/IP and runs check on the input to verify its exist and can be used, after the Domain/IP is verified continue to displaying information associated to the Domain/IP the user chosen.
{
	
	while true; # The start of the loop to check if the Domain/IP that the user typed are valid, exist and good to continue.
	do
		read -p " > Please Specify A Domain/IP Address To Scan: " DMN  # reading the user input and asking him to specify A Domain/IP to scan, and insert it into a variable named "DMN".

		if [[ -z "$DMN" ]]; # " [[ ]]" we use double bracket for more complex conditional expressions. The flag -z is to check if "DMN" variable is empty if so move to 'then' if its not empty move to  'else' statment.
		then
			echo
			sleep 1
			echo "[!] Invalid Domain/IP: Empty Text."
			sleep 1
			echo
		elif [[ "$DMN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; # 'elif' statment is alternative action if the previous conditions are not met. "[[ ]]" we use double bracket for more complex conditional expressions. "=~" checking if the string of the left matches the pattern on the right side. the pattern after the symbol representing a valid IPv4 address. if the string matches the pattern move on to 'then' statment, if it doesn't continue to 'else' statment.
		then
			# Check if it's a valid IP address using dig -x
			if dig -x "$DMN" |grep -iq "ANSWER SECTION";  # This command performs a reverse DNS lookup on the ip to find domain to the ip address. and then grep the word that mean the ip is belong to a domain and vaild ip address. moving to 'then' statment, if it didn't grep the word mean no domain belong to the ip and its invaild ip address moving to 'else' statment.
			then
				echo
				sleep 1        
				echo "[*] IP Address Validation Successful. Progressing..."
				sleep 2             
				break  # break the loop if the IP address is valid
			else
				echo
				sleep 1
				echo "[!] Invalid IP Address. Please Try Again."
				sleep 1
				echo
			fi
		else
			# In case its not ip and it's a domain the following output will be executed.
			if nslookup "$DMN" 2>/dev/null | grep -qi 'Non-'; # The nslookup command ask the  DNS to find an IP address that belong with this domain then using grep (flag -qi mean in quite mode and Ignore case) for the word "Non-" mean its vaild domain. if there is a match mean its vaild and moving to 'then' statment, if not matched so move to 'else' statment.
			then 
				echo
				sleep 1
				echo "[*] Domain Validation Successful. Progressing..."
				echo
				sleep 2 
				break  # break the loop if the domain is valid            
			else
				echo
				sleep 1
				echo "[!] Invalid Domain. Please Try Again..."
				sleep 1
				echo
			fi
		fi
	done  # End of the loop.
	echo
	echo
	echo "[?] Scaning The Domain/IP Address Might Take Few Seconds. Please Wait...  "
	SCANLOG  # Calling the function called "SCANLOG" 
	NMAPSCAN  # Calling the function called "NMAPSCAN" 
	WHOIS  # Calling the function called "WHOIS" 
	sleep 3
	SCAN=$(sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "nmap -p 22,21,80,443,25,3389,53 --open $DMN -Pn")  # Connecting via ssh to the server and scanning using nmap the user chosen Domain/IP (using -p to specify port number) scan for the 7 most known, when using "--open" its displaying only the open ports, and using "-Pn" to Skip host discovery and assumes that the target are online. and inserting it into a variable named "SCAN".
	ip=$(sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "nmap -p 22,21,80,443,25,3389,53 --open $DMN -Pn"| grep -oP '(\d+\.){3}\d+' | head -n 1) # using grep -oP to extract and print only the portions of the text that match the specified regular expression pattern, the pattern after extracts the stracture of an IPv4 address from the nmap output. The command head-n1 make sure to cut the first ip that appears. and inserting it into a variable named "ip".
	LOCATION=$(sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "geoiplookup $DMN "|awk -F, '{print $2}') # connecting to the ssh server and runing the 'geoiplookup' on the Domain/ip the user choose to reveal its associated country. and inserting it into a variable named "LOCATION".
	echo
	echo " > The IP Address Of The Domain/IP: $ip"
	echo
	sleep 3
	echo " > The Country Associated To The Domain/IP: $LOCATION"
	echo
	sleep 3
	echo "Displaying Few Open Ports That Are Open In The Domain/IP: "
	echo
	echo "Port:     Service:"
	sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USR@$IP "nmap -p 22,21,80,443,25,3389,53 --open $DMN -Pn"| grep open |awk '{print $1"    "$3}'  # connecting to the ssh server executing nmap scan for the according port numbers and grep the word open to display only the open ports, the using awk to print only the port number and service.
	sleep 4
	}
while true # Creating a loop for the user and ask him if he want to scan another domain/ip.
do
    FUNDMN  # Calling the function called "FUNDMN"

    echo
    echo "[!] The Scan Results Are Over. "
    echo
    sleep 1
    read -p " > Would You Like To Scan Another Domain/IP [y/n]: " yn  # After asking the user if he would like to scan another Domain/ip, if the answer is 'y' moving to 'else' statment inside the if statement, if it’s not equal to 'y' then moving to 'then'  inside the if statment that scan another Domain/IP.
    if [ "$yn" != "y" ];  # If the input that the user gave  equal to 'y' going to 'else' statment , if its not equal move to 'then' statment.
    then
        break  # breaking out of the loop if he dont want to scan another Domain/ip.
    else
        sleep 2
        clear
    fi
done

function END()  # Function for the end of the script which concludes the script and writing the files locations of the different scans that been executed in the script and the log file location.
{
	clear
	figlet -t -c -f slant This is The End Of The Script! |lolcat # using the command figlet that make the text font diffrent and convert it into ASCII, -t flag to spread on the screen, -c to center the text in the terminal, -f to Specifies the font in the case is 'slant' font. and the "|lolcat -a" to make the text colourful. 
	echo
	echo
	sleep 0.5
	echo "               > [!]  All The Nmap Scans That You Scan On The Domain/IP Are Saved In Your Desktop -> ~/Desktop/Project.files/Nmap.scan " |lolcat -a  # the "|lolcat -a" command to make the text colourful. 
	echo
	echo "               > [!]  All The Whois Scans That You Scan On The Domain/IP Are Saved In Your Desktop -> ~/Desktop/Project.files/Whois.scan " |lolcat -a  # the "|lolcat -a" command to make the text colourful. 
	echo
	echo "               > [!]  Your Scans, Data And Failed/Success Connections To SSH Was Saved Into A Log file -> ~/Desktop/Project.files/NR.log "|lolcat -a  # the "|lolcat -a" command to make the text colourful. 
	echo   
	echo
	echo
	echo 
	echo -e "              		                                      Press Any Key To Exit..." | lolcat -a  #using -e enables the interpretation of backslash ,and the "|lolcat -a" command to make the text colourful. 
	read -n 1 -s -r # This command will exit the function after receiving any key press. "-n 1" flag specifies that only one character should be read. -s  Causes the input to be silent and not displaying on screen, -r flag treating backslashes and  escape characters as literal characters.
	cmatrix & sleep 4; kill $! # the command cmatrix make visually dynamic and animated display of characters on the terminal screen. using sleep command to make it run for 4 seconds, and the "kill $!" command sends a signal to kill the most recently backgrounded process. The '$!' represents the process ID (PID) of the last background command.
	echo 
}	
END 

while true; # creating a loop for showing the menu a choice to display the files that was created ,displaying them in case he choose to and keep looping until user choose to exit.
do
    clear
    echo "[*] Before Exiting The Script You Can View The Files That Was Created..."
    sleep 2.5
    echo
    echo "[*] Choose The File You Want To Display:"
    echo
    sleep 1.5
    echo " 1) To Display The Log File Result."
    sleep 0.7
    echo " 2) To Display The Whois Scan File Result."
    sleep 0.7
    echo " 3) To Display The Nmap Scan File Result."
    

    echo
    sleep 1.7
    read -p " > Enter Your Choice (1-3) Or Any Key To Exit: " key  # reading the user input and insert it to variable named "key". if he choose something diffrent the 1-3 moving to *) and exiting the script.
	
    case $key in  # Using case statment to display the file the user choose inside the variable "key".
        1)
			echo
			echo
			echo "[*] Displaying The Log File... " 
			echo
			echo
			sleep 2.5
            cat ~/Desktop/Project.files/NR.log
			echo
			echo            
            ;;
        2)
			echo
			echo
			echo "[*] Displaying The Whois Scan File... " 
			echo 
			echo
			sleep 2.5			
            cat ~/Desktop/Project.files/Whois.scan
			echo
			echo            
            ;;
        3)
			echo
			echo     
			echo "[*] Displaying The Nmap Scan File... " 
			echo
			echo
			sleep 2.5       
            cat ~/Desktop/Project.files/Nmap.scan
			echo
			echo            
            ;;
        *)
			echo
            echo "Exiting The Script... Goodbye!"
            exit 0 #exiting the scipt
            ;;
    esac
      		
      read -p " > Press Any Key To Go Back To The Menu, Or Type 'exit' To Exit: " # asking the user if he want to exit by typing 'exit' or pressing any key to go make to the menu.
    # Check if the user typed "exit" and exit the script
    if [[ "$REPLY" == "exit" ]];  #if the replay of the last command equal to 'exit' moving to 'then' statment and exiting the script.
    then
		echo
        echo "   Exiting The Script... Goodbye!"
        sleep 3
        exit 0  # exiting the script.
    fi
done  # end of the loop.
