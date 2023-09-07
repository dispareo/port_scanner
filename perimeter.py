#!/usr/bin/python3
import sys
import nmap
import argparse

#These are the most important points as determined quite unscientifically by me
ports = [21,22,23,25,80,135,139,443,445,8000,8080]

#We have to have a cheesy greeting, right?
print('*********************************************')
print('*                                           *')
print('* Dispareo Security\'s Super Secret $cann3r  *')
print('*                                           *')
print('*********************************************\n\n')

#What IP are we gonna check?
target = '127.0.0.1'
scanner = nmap.PortScanner()

#mmk, now let's scan them ports uno a uno. Este es uy dispacio :( pero ya no se como hacerlo mas rapido. I guess it's just part of using python

#first, let's take the ports from above, scan 'em, and capture the results of the port scans
#The nmap library has lots of info in the dictionary, but we only care about a few parts of the dictionary
#Also, books. We care about books. And how stupid banning books is
#Aiight, back to coding. 

print(f'[*][*][*] Scanning ports, please wait...')
for i in (ports):
	# scan the target ports and capture the output
    ta_da = scanner.scan(target,str(i))
    ta_da = ta_da['scan'][target]['tcp'][i]['state']
    #Now that we have the input, let's print the open ports. 
    #Originally, I also shared the ones that were closed, but that seems a bit superfluous
    if "open" in ta_da:
        print(f'[*] Port {i} is {ta_da}. Make sure this is intentional!')

print('\n----------------------------------------------------')
print('|    [*]  Initial port scan is complete  [*]       |')
print('----------------------------------------------------\n')
#We're going to ask for special ports via input to check, too
#This would be helpful for port change control

#First, ask the user what ports they wanna check
eingang = input("[?] Are there particular ports you want to add?\n[!] Please use a comma to separate port numbers (e.g. 22,80,443)\n")
print('\n----------------------------------------------------\n')

#Take the input and split them ports up!
ports_to_knock = eingang.split(',')

#k, now we scan those ports basically using the same function as we did before
# first, we need to do a sanity check - errrr, input check. If it's blank, we exit
#so, we wrap the function in an operator. 
if(eingang != ''):
    print(f'[*] Checking requested ports {ports_to_knock}')
    for j in ports_to_knock: #not another "i" loop :(
        did_the_FW_guy_mess_something_up = scanner.scan(target, str(j))
        did_the_FW_guy_mess_something_up = did_the_FW_guy_mess_something_up['scan'][target]['tcp'][int(j)]['state']
        if "open" in did_the_FW_guy_mess_something_up:
            print(f'[!] Check port {j} cuz it looks like it\'s still open')

#If there is no input given, call wrap it up
else:
    print('Go enjoy a smooth bourbon and this meme, your day is done')
    print('https://i.kym-cdn.com/entries/icons/original/000/030/967/spongebob.jpg\n')
    print('If you used the --topport or -t flag, check output below:')
    print('----------------------------------------------------')

#Now that the basic stuff is done, let's toss in an option for a bigger scan
#because why not? We need to overcomplicate something that already worked fine, because that's what we do. 
#Add in our flag. Our lonely, single flag. 
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--topports", action='store_true')
args = parser.parse_args()


#If the user wants to scan all the top ports, we will use python to basically just call nmap top 1000 ports
#I don't like the ugly output, but that's a problem for future Mark
#Future Mark solved it :)

#If the '-t' or '--topport' flag is on, scan the top 1K ports
if args.topports:
    call_me = nmap.PortScanner()
    call_me.scan(hosts=target, arguments="--top-ports 1000")
    #Now, for some parsing and sorting

    #This little nested loop was very handy
    #Sourced from https://pypi.org/project/python-nmap/
    for host in call_me.all_hosts():
        print('\n----------------------------------------------------')
        print('Host : %s (%s)' % (host, call_me[host].hostname()))
        print('State : %s' % call_me[host].state())
        #Now that we have the host and up/down state, now we print off the open ports and protocols
        #I don't know that we really need the protocol, but sometimes it is helpful
        #We do also have to sort by protocol anyway to sort the open ports
        for proto in call_me[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = call_me[host][proto].keys()
            #Now that we
            sorted(lport)
            for port in lport:
                print ('port : %s\tstate : %s' % (port, call_me[host][proto][port]['state']))
