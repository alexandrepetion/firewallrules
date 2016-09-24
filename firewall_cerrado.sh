#Taller de Iptables
#Julio Cesar Gomez Castano
#agosto 23  del 2016

#Deja el firewall con las politicas bien definidas

#Defina la variables
inter="ens33"
mi_ip="10.10.11.191"
red_lan="10.10.11.0/24"
pro_ip="10.10.11.156"
cli_ip="10.10.11.131"
stv_ip="10.10.11.157"
dns_ip="8.8.8.8"
dns2_ip="181.118.150.20"
nsuao_ip="181.118.150.58"
#Punto 13 Verifica politicas actuales
iptables -L

#Borrar las reglas
iptables -F

#punto 5 - 12 deja todo cerrado
#Fijar las politicas en cerrado
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

#punto 8 Permite la comunicacion con el localhost
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT


#punto 14 Permite realizar ping a la red local 10.10.11.0/24
#punto 18 Se borra la regla INPUT
#iptables -A INPUT  -i $inter -p icmp -s $red_lan -d $mi_ip -j ACCEPT
iptables -A OUTPUT  -o $inter -p icmp -d $red_lan -s $mi_ip -j ACCEPT

#punto 15 permite todo tipo de  comunicacion ipaddress profesor
iptables -A OUTPUT -s $mi_ip -d $pro_ip -j ACCEPT
iptables -A INPUT  -s $pro_ip -d $mi_ip -j ACCEPT
#conexion a mi IP destion via ssh
iptables -A OUTPUT -s $mi_ip -d $cli_ip -j ACCEPT
iptables -A INPUT  -s $cli_ip -d $mi_ip -j ACCEPT
#punto 19 Permite consultas DNS
iptables -A OUTPUT -s $mi_ip -d $dns_ip -p udp --sport 1024:65535 --dport 53 -j ACCEPT
iptables -A INPUT  -s $dns_ip -d $mi_ip -p udp --sport 1024:65535 --dport 53 -j ACCEPT
#punto 20 Permite consulas al DNS primario
iptables -A OUTPUT -d $dns2_ip -s $mi_ip -p udp --sport 1024:65535 --dport 53 -j ACCEPT
iptables -A INPUT  -s $mi_ip -d $dns2_ip -p udp --sport 1024:65535 --dport 53 -j ACCEPT
#punto 21 Permite realizar consulta uao
iptables -A OUTPUT -s $mi_ip -d $nsuao_ip -p tcp --sport 1024:65535 --dport 80  -j ACCEPT
iptables -A INPUT  -s $nsuao_ip -d $mi_ip -p tcp --sport 80 --dport 1024:65535  -j ACCEPT
#punto 22 Acceso http/https
iptables -A OUTPUT -s $mi_ip -d 0.0.0.0/0 -p tcp --dport http --sport 1024:65535  -j ACCEPT
iptables -A INPUT  -s 0.0.0.0/0 -d $mi_ip -p tcp --sport http --dport 1024:65535  -j ACCEPT

iptables -A OUTPUT -s $mi_ip -d 0.0.0.0/0 -p tcp --dport https --sport 1024:65535 -j ACCEPT
iptables -A INPUT  -s 0.0.0.0/0 -d $mi_ip -p tcp --sport https --dport 1024:65535 -j ACCEPT
#punto 23 SSH
echo 23
iptables -A OUTPUT -s $mi_ip -d $stv_ip -p tcp --sport ssh  -j ACCEPT
iptables -A INPUT  -s $stv_ip -d $mi_ip -p tcp --dport ssh  -j ACCEPT

iptables -A OUTPUT -s $mi_ip -d $stv_ip -p tcp --dport ssh  -j ACCEPT
iptables -A INPUT  -s $stv_ip -d $mi_ip -p tcp --sport ssh  -j ACCEPT
