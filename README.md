Step-by-step on how to run mininet

before we start running,dont forget to clone these files:
  - application.py
  - simple-topo.py


Step 1: Mininet setup
On UTM terminal (I use Mac), run: sudo mn --custom ~/DRTP-v25/simple-topo.py --topo mytopo --controller=remote

Step 2: Open the terminal for the Hots
Now you are on mininet>, run : xterm h1 h2

Step 3: IP check
On both h1 and h2, run: ifconfig
(Remember the Ip, I got 10.0.1.2)

Step 4: Start the Server on h2
On h2 terminal, run: python3 application.py -s -i 10.0.1.2 -p 9099

Step 5: Make a test file and start the Client on h1:
To make a test file (3Kb) on h1 terminal, run: dd if=/dev/zero of=testfile.txt bs=1024 count=3
To start the Client, run: python3 application.py -c -i 10.0.1.2 -p 9099 -f testfile.txt

Step 6: Verify the results 
On both h1 and h2, run: ls

You are now finished and should get expected result. after you ran "ls" on h2, the Server should save the file as received_file and the Client should have Throughput in bits/s
