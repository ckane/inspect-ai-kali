FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get dist-upgrade -y && apt-get install -y fonts-unifont
RUN apt-get install -y postgresql metasploit-framework
RUN apt-get install -y playwright
RUN apt-get install -y python3 python3-venv python-is-python3
# RUN python -m venv /opt/inspect_tool_support
# RUN /opt/inspect_tool_support/bin/pip install inspect_tool_support 
# RUN /opt/inspect_tool_support/bin/inspect-tool-support post-install --no-web-browser
RUN apt-get install -y burpsuite sudo bind9-dnsutils iputils-ping less
RUN apt-get install -y docker-cli docker-buildx docker-compose docker-doc
RUN apt-get install -y wapiti dirbuster dirsearch ncat websploit whatweb watobo sqlmap
RUN apt-get install -y nmap tcpdump dialog dirb
RUN apt-get install -y nikto gobuster wordlists seclists dictionaries-common crunch
RUN apt-get install -y exploitdb exploitdb-papers exploitdb-bin-sploits
RUN apt-get install -y mcp-kali-server pompem wpscan hydra enum4linux npm

# Update exploitdb / searchsploit
RUN /usr/bin/searchsploit -u || echo Done

ENV PGPORT=5432
RUN service postgresql start && msfdb init
RUN msfconsole -x "exit"

# Initialize profiles
RUN <<EOF
echo "unset LD_LIBRARY_PATH" >> /root/.bashrc
echo "unset LD_LIBRARY_PATH" >> /root/.profile
echo "unset LD_LIBRARY_PATH" >> /root/.zshrc
echo "unset LD_LIBRARY_PATH_ORIG" >> /root/.bashrc
echo "unset LD_LIBRARY_PATH_ORIG" >> /root/.profile
echo "unset LD_LIBRARY_PATH_ORIG" >> /root/.zshrc
echo "alias dirbuster=\"/usr/bin/dirbuster -H\"" >> /root/.bashrc
echo "alias dirbuster=\"/usr/bin/dirbuster -H\"" >> /root/.profile
echo "alias dirbuster=\"/usr/bin/dirbuster -H\"" >> /root/.zshrc
EOF

# Create an initialization script that runs the kali-server-mcp and then
# mcp-server client process, once it is ready
COPY <<EOF /kali-mcp.sh
#!/bin/bash
kali-server-mcp --port 15555 >& /dev/null &
sleep 15
exec mcp-server --server http://localhost:15555
EOF
RUN chmod a+x /kali-mcp.sh

# Link dirb wordlists to a more common place
RUN mkdir -p /usr/share/wordlists
RUN ln -s ../dirb/wordlists /usr/share/wordlists/dirb

# ENV PATH="$PATH:/opt/inspect_tool_support/bin"
