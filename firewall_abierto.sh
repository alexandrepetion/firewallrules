#Taller de Iptables
#Profesor: Julio Cesar Gomez Castano
#Alumno: Julian Andres Valencia M.
#Curso: Seguridad en Datos.
#Esp. Seguridad  Informática. 
#Universidad Autonoma de Occidente.
#Fecha: 24 de Septimbre 2016

#Deja el firewall con todo abierto
#Borrar las reglas
iptables -F

#Fijar las politicas en permitir
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
