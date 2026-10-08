# R4, R5, R6 checklist (run on the real VMs)

Every screenshot must show the command that produced it, be readable, and be
taken on your four VMs. Do the R4 steps first.

## Setup (once)
On **client** and **server** VMs, stop the kernel sending RSTs:

    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

Make test files on the **server** VM:

    mkdir -p ~/www && cd ~/www
    echo '<html><body><h1>Hello</h1></body></html>' > index.html
    head -c 300000 /dev/urandom > big.bin          # must be >= 100 KB
    md5sum index.html big.bin                      # screenshot this too

## R4: your client vs a standard web server on the server VM

Server VM:

    cd ~/www && python3 -m http.server 8000

Client VM (screenshot each command with its output):

    sudo ./client/run-client http://10.10.3.10:8000/index.html -o c_index.html; echo "exit=$?"
    sudo ./client/run-client http://10.10.3.10:8000/big.bin -o c_big.bin; echo "exit=$?"
    curl -s http://10.10.3.10:8000/index.html -o k_index.html
    curl -s http://10.10.3.10:8000/big.bin -o k_big.bin
    md5sum c_index.html k_index.html c_big.bin k_big.bin

Pass condition: exit=0 both times, and each pair of md5sums is identical.
Also worth showing: `sudo ./client/run-client http://10.10.3.10:8000/nope -o x; echo $?`
prints `exit=1`.

## R5: curl, wget and your client against YOUR server

Server VM:

    sudo ./server/run-server -p 8080 -d ~/www --log server.log

Client VM:

    curl -s http://10.10.3.10:8080/big.bin -o curl_big.bin
    wget -q http://10.10.3.10:8080/big.bin -O wget_big.bin
    sudo ./client/run-client http://10.10.3.10:8080/big.bin -o my_big.bin; echo "exit=$?"
    md5sum curl_big.bin wget_big.bin my_big.bin
    # compare with: md5sum big.bin   (run on the server VM)

Pass condition: all four md5sums are identical. The server handles one
connection at a time, so run the commands one after another.

## R6: capture of one complete connection plus short description

Client VM, in a second terminal before running the client:

    sudo tcpdump -nn -i <IF_D or IF_A> tcp port 8080 -w /tmp/conn.pcap   # then Ctrl+C
    sudo tcpdump -nn -r /tmp/conn.pcap                                   # screenshot this

Screenshot the full handshake, data, FIN exchange. Write a short paragraph
each on: retransmission (timeout, what triggers it), out-of-order buffering,
and congestion control (cwnd / ssthresh behaviour). Partner A writes this
paragraph from `raw_tcp.py`, since it describes the TCP engine. If those
features are not implemented yet, describe only what is implemented.

## Extra checks before zipping
- `python tests/test_http_logic.py` prints ALL OK
- `--log` works: `cat server.log` shows `SEND`/`RECV` lines in the exact format
- `ls -l client/run-client server/run-server` shows executable (x) bits
- `python3 tools/package.py ENTRY1 ENTRY2 --strip-mock` prints no ERROR lines
