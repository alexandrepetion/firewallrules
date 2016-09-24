#Taller de Iptables
#Julio Cesar Gomez Castano
#agosto 14  del 2016

#Deja el firewall con todo abierto

#Borrar las reglas
iptables -F


#Fijar las politicas en permitir
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
