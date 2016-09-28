#Taller de Iptables - Guia Laboratorio 3.
#Profesor: Julio Cesar Gomez Castano
#Alumno: Julian Andres Valencia M.
#Curso: Seguridad en Datos.
#Esp. Seguridad  Informática. 
#Universidad Autonoma de Occidente.
#Fecha: 24 de Septimbre 2016

#Deja el firewall con las politicas bien definidas

#Variables globales parametrizadas para aplicaciones de rules firewall.

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
iptables -L -v -n

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

#punto 10 Borrado politica INPUT del localhost
iptables -D INPUT -i lo -j ACCEPT

#punto 11 Agredando nuevamente la politica INPUT
iptables -A INPUT -i lo -j ACCEPT

#punto 14 habilitando protocolo icmp a la red local 10.10.11.0/24
iptables -A INPUT  -i $inter -p icmp -s $red_lan -d $mi_ip -j ACCEPT
iptables -A OUTPUT -o $inter -p icmp -d $red_lan -s $mi_ip -j ACCEPT

#punto 15 permite todo tipo de  comunicación con la direccción ip del profesor.
iptables -A OUTPUT -s $mi_ip -d $pro_ip -j ACCEPT
iptables -A INPUT  -s $pro_ip -d $mi_ip -j ACCEPT

#punto 18 borrra la politica INPUT establecida en el punto 14.
iptables -D INPUT  -i $inter -p icmp -s $red_lan -d $mi_ip -j ACCEPT
 
#punto 19 Permite consultas DNS secundario [8.8.8.8].
iptables -A OUTPUT -s $mi_ip -d $dns_ip -p udp --sport 1024:65535 --dport 53 -j ACCEPT
iptables -A INPUT  -s $dns_ip -d $mi_ip -p udp --dport 1024:65535 --sport 53 -j ACCEPT

#punto 20 Permite consulas al DNS primario de la red Wan del a universidad [181.118.150.20].
iptables -A OUTPUT -d $dns2_ip -s $mi_ip -p udp --sport 1024:65535 --dport 53 -j ACCEPT
iptables -A INPUT  -s $mi_ip -d $dns2_ip -p udp --dport 1024:65535 --sport 53 -j ACCEPT

#punto 21 Permite realizar consulta a la url www.uao.edu.co [181.118.150.58].
iptables -A OUTPUT -s $mi_ip -d $nsuao_ip -p tcp --sport 1024:65535 --dport 80 -j ACCEPT
iptables -A INPUT  -s $nsuao_ip -d $mi_ip -p tcp --sport 80 --dport 1024:65535 -j ACCEPT

#punto 22 Acceso completo http/https.
#[via pto 80]
iptables -A OUTPUT -s $mi_ip -d 0.0.0.0/0 -p tcp --dport http --sport 1024:65535  -j ACCEPT
iptables -A INPUT  -s 0.0.0.0/0 -d $mi_ip -p tcp --sport http --dport 1024:65535  -j ACCEPT
#[via pto 443]
iptables -A OUTPUT -s $mi_ip -d 0.0.0.0/0 -p tcp --dport https --sport 1024:65535 -j ACCEPT
iptables -A INPUT  -s 0.0.0.0/0 -d $mi_ip -p tcp --sport https --dport 1024:65535 -j ACCEPT

#punto 23 Server Acceso SSH [10.10.11.191] de un solo equipo de la LAN [10.10.11.157].
iptables -A OUTPUT -o $inter -d $mi_ip -s $stv_ip -p tcp --sport 1024:65535 --dport ssh -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $inter -d $stv_ip -s $mi_ip -p tcp --sport ssh --dport 1024:65535 -m state --state ESTABLISHED     -j ACCEPT

#punto 24 lado Cliente [10.10.11.191] accediendo al server SSH  LAN [10.10.11.157].
iptables -A INPUT  -i $inter -d $mi_ip -s $stv_ip -p tcp --sport 22  --dport 1024:65535 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $inter -d $stv_ip -s $mi_ip -p tcp --sport 1024:65535 --dport 22  -m state --state ESTABLICHED     -j ACCEPT
  
#punto 25 Permite visibilidad LAN [10.10.11.0/24] del server web local[http://10.10.11.191:80].
iptables -A OUTPUT -s $mi_ip -d $red_ip -p tcp --sport 80 --dport 1024:65535 -m state --state NEW,ESTABLISHED  -j ACCEPT
iptables -A INPUT  -s $red_ip -d $mi_lan -p tcp --sport 1024:65535 --dport 80 -m state --state ESTABLISHED     -j ACCEPT
#punto 25.1 Permite visibilidad LAN [10.10.11.0/24] del server web local[http://10.10.11.191:8080].
iptables -A OUTPUT -s $mi_ip -d $red_ip -p tcp --sport 8080 --dport 1024:65535 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -s $red_ip -d $mi_ip -p tcp --sport 1024:65535 --dport 8080 -m state --state ESTABLISHED     -j ACCEPT

#punto 26 Permite a la red LAN [10.10.11.0/24] accesar a los servicios instalados en el servidor(www,ssh,ftp, etc)
#[www]
iptables -A OUTPUT -s $mi_ip -d $red_ip -p tcp --sport 80 --dport 1024:65535 -m state --state NEW,ESTABLISHED  -j ACCEPT
iptables -A INPUT  -s $red_ip -d $mi_lan -p tcp --sport 1024:65535 --dport 80 -m state --state ESTABLISHED     -j ACCEPT
#[ssh]
iptables -A OUTPUT -o $inter -d $mi_ip -s $stv_ip -p tcp --sport 1024:65535 --dport ssh -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $inter -d $stv_ip -s $mi_ip -p tcp --sport ssh --dport 1024:65535 -m state --state ESTABLISHED     -j ACCEPT
#[ftp]
iptables -A INPUT -p tcp --sport 1024:65535 --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 1024:65535 --dport 20 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 21 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

 iptables -A INPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -p tcp -m tcp --dport 21 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 
 iptables -A INPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -p tcp -m tcp --dport 20 -m conntrack --ctstate ESTABLISHED -j ACCEPT 
 iptables -A INPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -p tcp -m tcp --sport 1024: --dport 1024: -m conntrack --ctstate ESTABL
