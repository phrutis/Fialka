import os
import requests
import time

file = open("addresses.txt")
lines = file.readlines()

for line in lines:
   print(line)
   response = requests.get("https://blockchain.info/q/pubkeyaddr/" + line)
   try:
      print(response.text)
   except ValueError:
      print("Failure to retrieve data from block explorer \n")
   time.sleep(1)
   if response.status_code == 404:
      pass
   elif response.status_code == 200:
       print("We found pubkey! \n")
       
       file = open("pubkeys.txt", "a+")
       file.write(str(response.text) + "\n")
       file.close()
