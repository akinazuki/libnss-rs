FROM debian
RUN apt-get update && apt-get install openssh-server rsyslog -y && /usr/bin/ssh-keygen -A -N ''
RUN mkdir /run/sshd
COPY ./ssh_auth.sh /opt/ssh_auth.sh
RUN chmod +x /opt/ssh_auth.sh
RUN service rsyslog start
CMD ["/usr/sbin/sshd", "-D"]