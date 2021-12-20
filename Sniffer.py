import socket
import struct
import binascii
import textwrap

def main():
    conexion = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data,direccion = conexion.recvfrom(65536)
        mac_destino,mac_origen,tipo_ethernet,datos = ethernet_frame(raw_data)
        #CASO IPv4
        if (tipo_ethernet=="08:00"):
            protocolo_ethernet="IPv4"
        #CASO ARP
        elif (tipo_ethernet=="08:06"):
            protocolo_ethernet="ARP"
        #CASO RARP
        elif (tipo_ethernet=="08:35"):
            protocolo_ethernet="RARP"
        #CASO IPv6
        else:
            protocolo_ethernet="IPv6"
        imprimirSignos()
        print("\nEthernet frame: ")
        print("\t-MAC Destino: {}\n\t-MAC Origen: {}\n\t-Tipo: {}\n\t-Protocolo: {}".format(mac_destino,mac_origen,tipo_ethernet,protocolo_ethernet))
        #CASO IPv4
        if protocolo_ethernet=="IPv4":
            protocolo_mensaje,datos=paquete_ipv4(datos)
            if (protocolo_mensaje=="ICMPv4"):
                datos=paquete_icmpv4(datos)
            elif (protocolo_mensaje=="TCP"):
                servicio_origen,servicio_destino,datos=paquete_tcp(datos)
                if (servicio_origen=="DNS" or servicio_destino=="DNS"):
                    datos=paquete_dns(datos)
            elif (protocolo_mensaje=="UDP"):
                servicio_origen,servicio_destino,datos=paquete_udp(datos)
                if (servicio_origen=="DNS" or servicio_destino=="DNS"):
                    datos=paquete_dns(datos)
        #CASO ARP
        elif protocolo_ethernet=="ARP":
            datos=paquete_arp(datos)
        #CASO RARP
        elif protocolo_ethernet=="RARP":
            datos=paquete_rarp(datos)
        #CASO IPv6
        else:
            ipv6_mensaje,datos=paquete_ipv6(datos)
            if ipv6_mensaje=="ICMPv6":
                datos=paquete_icmpv6(ipv6_mensaje,datos)
            elif (ipv6_mensaje=="TCP"):
                servicio_origen,servicio_destino,datos=paquete_tcp(datos)
                if (servicio_origen=="DNS" or servicio_destino=="DNS"):
                    datos=paquete_dns(datos)
            elif (ipv6_mensaje=="UDP"):
                servicio_origen,servicio_destino,datos=paquete_udp(datos)
                if (servicio_origen=="DNS" or servicio_destino=="DNS"):
                    datos=paquete_dns(datos)
        imprimirSignos()

#Imprimir separacion
def imprimirSignos():
    i=0
    while(i<80):
        print("-",end="")
        i=i+1
#Desempaquetar el paquete de ethernet
def ethernet_frame(datos):
    mac_destino,mac_origen,protocolo=struct.unpack('! 6s 6s 2s',datos[:14]);
    return get_direccion_mac(mac_destino),get_direccion_mac(mac_origen),get_direccion_mac(protocolo),datos[14:]

#Regresar el formato de la direccion MAC
def get_direccion_mac(bytes_direccion):
    bytes_string = map('{:02x}'.format,bytes_direccion)
    return ':'.join(bytes_string).upper()

#Desempaquetar el paquete IPv4
def paquete_ipv4(datos):
    tipoVersion="";retardo="";rendimiento="";fiabilidad="";flag1="";flag2="";flag3=""
    longVersion=datos[0]
    version=longVersion >> 4
    longCabecera=(longVersion & 15) * 4
    binary_string= bin(int(binascii.hexlify(datos[1:2]), 16))[2:].zfill(8)
    if (binary_string[0:3]=="000"):
        tipoVersion="De rutina."
    elif (binary_string[0:3]=="001"):
        tipoVersion="Prioritario."
    elif (binary_string[0:3]=="010"):
        tipoVersion="Inmediato."
    elif (binary_string[0:3]=="011"):
        tipoVersion="Relámpago."
    elif (binary_string=="100"):
        tipoVersion="Invalidación relámpago."
    elif (binary_string=="101"):
        tipoVersion="Procesando llamada critica y de emergencia"
    elif (binary_string=="110"):
        tipoVersion="Control de trabajo de Internet."
    else:
        tipoVersion="Control de red."
    if (binary_string[3]=="0"):
        retardo="Normal"
    else:
        retardo="Alto"
    if (binary_string[4]=="0"):
        rendimiento="Normal"
    else:
        rendimiento="Alto"
    if (binary_string[5]=="0"):
        fiabilidad="Normal"
    else:
        fiabilidad="Alto"
    binary_string= bin(int(binascii.hexlify(datos[5:7]), 16))[2:].zfill(8)
    identificador=aDecimal(binary_string)
    binary_string= bin(int(binascii.hexlify(datos[7:9]), 16))[2:].zfill(8)
    flags=binary_string
    if (flags[0]=="0"):
        flag1="Reservado"
    if (flags[1]=="0"):
        flag2="Divisible"
    else:
        flag2="No divisible"
    if (flags[2]=="0"):
        flag3="Último fragmento"
    else:
        flag3="Fragmento intermedio"
    checkSum=':'.join(map('{:02x}'.format,datos[10:12])).upper()
    ttl,proto,origen,destino=struct.unpack('! 8x B B 2x 4s 4s',datos[:20])
    if (proto==1):
        protocolo="ICMPv4"
    elif (proto==6):
        protocolo="TCP"
    elif (proto==17):
        protocolo="UDP"
    elif (proto==58):
        protocolo="ICMPv6"
    elif (proto==118):
        protocolo="STP"
    else:
        protocolo="SMP"
    print("\t\t-Version: {}\n\t\t-Longitud Cabecera: {}\n\t\t-Tiempo de vida: {}".format(version,longCabecera,ttl))
    print("\t\t-Prioridad: ",tipoVersion)
    print("\t\t-Retardo: ",retardo)
    print("\t\t-Rendimiento: ",rendimiento)
    print("\t\t-FiabilidadL ",fiabilidad)
    print("\t\t-Identificador: ",identificador)
    print("\t\t-Flags: 1 = ",flag1,"2 = ",flag2,"3 = ",flag3)
    print("\t\t-Posicion del fragmento: ",aDecimal(flags[3:16]))
    print("\t\t-Suma de cabecera: ",checkSum)
    print("\t\t-Protocolo: {}\n\t\t-Direccion IP origen: {}\n\t\t-Direccion IP destino: {}".format(protocolo,ipv4(origen),ipv4(destino)))
    return protocolo,datos[20:]
#Retornar el formato de la direccion IPv4
def ipv4(direccion):
    return '.'.join(map(str,direccion))
#Retornar el formato de la direccion IPv6
def ipv6(direccion):
    ip1=''.join(map('{:02x}'.format,direccion[0:2]))
    ip2=''.join(map('{:02x}'.format,direccion[2:4]))
    ip3=''.join(map('{:02x}'.format,direccion[4:6]))
    ip4=''.join(map('{:02x}'.format,direccion[6:8]))
    ip5=''.join(map('{:02x}'.format,direccion[8:10]))
    ip6=''.join(map('{:02x}'.format,direccion[10:12]))
    ip7=''.join(map('{:02x}'.format,direccion[12:14]))
    ip8=''.join(map('{:02x}'.format,direccion[14:16]))
    #ip1=str(ip1);ip2=str(ip2);ip3=str(ip3);ip4=str(ip4);ip5=str(ip5);ip6=str(ip6);ip7=str(ip7);ip8=str(ip8)
    return '.'.join((ip1,ip2,ip3,ip4,ip5,ip6,ip7,ip8)).upper()

#Desempaquetar el paquete ICMP
def paquete_icmpv4(datos):
    (icmp_tipo,codigo,checksum)=struct.unpack('! B B H',datos[:4])
    print("\t\t---------------->ICMPv4:")
    print("\t\t-Mensaje informativo: ",icmp_tipo)
    print("\t\t-Código de error: ",codigo)
    print("\t\t-CheckSum: ",checksum)
    return datos[4:]
#Paquete ARP
def paquete_arp(datos):
    tipoHardware="";bytesHardware="";
    binary_string = bin(int(binascii.hexlify(datos[0:2]), 16))[2:].zfill(8)
    bytesHardware=binary_string
    numHardware=aDecimal(bytesHardware)
    numHardware=aDecimal(bytesHardware)
    if (numHardware==1):
        tipoHardware="Ethernet (10 Mb)"
    elif (numHardware==6):
        tipoHardware="IEEE 802 Networks"
    elif (numHardware==7):
        tipoHardware="ARCNET"
    elif (numHardware==15):
        tipoHardware="Frame Relay"
    elif (numHardware==16):
        tipoHardware="Asynchronous Transfer Mode (ATM)"
    elif (numHardware==17):
        tipoHardware="HDLC"
    elif (numHardware==18):
        tipoHardware="Fibre Channel"
    elif (numHardware==19):
        tipoHardware="Asynchronous Transfer Mode (ATM)"
    else:
        tipoHardware="Seial Line"
    #Tipo de protocolo
    protocolo="";tipoProtocolo=""
    tipoProtocolo=':'.join(map('{:02x}'.format,datos[2:4])).upper()
    if (tipoProtocolo=="08:00"):
        protocolo="IPv4"
    elif (tipoProtocolo=="08:06"):
        protocolo="ARP"
    elif (tipoProtocolo=="08:35"):
        protocolo="RARP"
    else:
        protocolo="IPv6"
    #Longitud direccion hardware
    longHardware=0;
    longHardware=aDecimal(datos[4:5])
    #Longitud direccion protocolo
    longProtocolo=0;
    longProtocolo=aDecimal(datos[5:6])
    #Bytes operacion
    bytesOperacion="";codigoOperacion="";
    bytesHardware=datos[6:8]
    numeroOperacion=aDecimal(bytesHardware)
    if (numeroOperacion==1):
        codigoOperacion="Solicitud ARP"
    elif (numeroOperacion==2):
        codigoOperacion="Respuesta ARP"
    elif (numeroOperacion==3):
        codigoOperacion="Solicitud RARP"
    else:
        codigoOperacion="Respuesta RARP"
    #Direccion hardware emisor
    hardwareEmisor=get_direccion_mac(datos[8:14])
    #Direccion IP emisor
    ipEmisor=ipv4(datos[14:18])
    #Direccion fardware receptor
    hardwareReceptor=get_direccion_mac(datos[18:24])
    #Direccion IP receptor
    ipReceptor=ipv4(datos[24:28])
    print("\t\t-Tipo de hardware: ",tipoHardware)
    print("\t\t-TIpo de protocolo: ",protocolo)
    print("\t\t-Longitud dirección hardware: ",longHardware)
    print("\t\t-Longitud dirección protocolo: ",longProtocolo)
    print("\t\t-Código de operación: ",codigoOperacion)
    print("\t\t-Dirección hardware emisor: ",hardwareEmisor)
    print("\t\t-Dirección IP emisor: ",ipEmisor)
    print("\t\t-Dirección hardware receptor: ",hardwareReceptor)
    print("\t\t-Dirección IP receptor: ",ipReceptor)
    return datos[28:]
#Paquete RARP
def paquete_rarp(datos):
    tipoHardware="";bytesHardware="";
    binary_string = bin(int(binascii.hexlify(datos[0:2]), 16))[2:].zfill(8)
    bytesHardware=binary_string
    numHardware=aDecimal(bytesHardware)
    numHardware=aDecimal(bytesHardware)
    if (numHardware==1):
        tipoHardware="Ethernet (10 Mb)"
    elif (numHardware==6):
        tipoHardware="IEEE 802 Networks"
    elif (numeHardware==7):
        tipoHardware="ARCNET"
    elif (numHardware==15):
        tipoHardware="Frame Relay"
    elif (numHardware==16):
        tipoHardware="Asynchronous Transfer Mode (ATM)"
    elif (numHardware==17):
        tipoHardware="HDLC"
    elif (numHardware==18):
        tipoHardware="Fibre Channel"
    elif (numHardware==19):
        tipoHardware="Asynchronous Transfer Mode (ATM)"
    else:
        tipoHardware="Seial Line"
    #Tipo de protocolo
    protocolo="";tipoProtocolo=""
    tipoProtocolo=datos[2:4]
    if (tipoProtocolo[1]==b'x\00'):
        protocolo="IPv4"
    elif (tipoProtocolo[1]==b'x\06'):
        protocolo="ARP"
    elif (tipoProtocolo[1]==b'x\35'):
        protocolo="RARP"
    else:
        protocolo="IPv6"
    #Longitud direccion hardware
    longHardware=0;
    longHardware=aDecimal(datos[4:5])
    #Longitud direccion protocolo
    longProtocolo=0;
    longProtocolo=aDecimal(datos[5:6])
    #Bytes operacion
    bytesOperacion="";codigoOperacion="";
    bytesHardware=datos[6:8]
    numeroOperacion=aDecimal(bytesHardware)
    if (numeroOperacion==1):
        codigoOperacion="Solicitud ARP"
    elif (numeroOperacion==2):
        codigoOperacion="Respuesta ARP"
    elif (numeroOperacion==3):
        codigoOperacion="Solicitud RARP"
    else:
        codigoOperacion="Respuesta RARP"
    #Direccion hardware emisor
    hardwareEmisor=get_direccion_mac(datos[8:14])
    #Direccion IP emisor
    ipEmisor=ipv4(datos[14:18])
    #Direccion fardware receptor
    hardwareReceptor=get_direccion_mac(datos[18:24])
    #Direccion IP receptor
    ipReceptor=ipv4(datos[24:28])
    print("\t\t-Tipo de hardware: ",tipoHardware)
    print("\t\t-TIpo de protocolo: ",protocolo)
    print("\t\t-Longitud dirección hardware: ",longHardware)
    print("\t\t-Longitud dirección protocolo: ",longProtocolo)
    print("\t\t-Código de operación: ",codigoOperacion)
    print("\t\t-Dirección hardware emisor: ",hardwareEmisor)
    print("\t\t-Dirección IP emisor: ",ipEmisor)
    print("\t\t-Dirección hardware receptor: ",hardwareReceptor)
    print("\t\t-Dirección IP receptor: ",ipReceptor)
    return datos[28:]
#Paquete IPv6
def paquete_ipv6(datos):
    trafico="";tipoVersion=""
    binary_string = bin(int(binascii.hexlify(datos), 16))[2:].zfill(8)
    versionDecimal=aDecimal(binary_string[0:4])
    #Tipo version
    trafico=binary_string[4:12]
    if (trafico[0:3]=="000"):
        tipoVersion="De rutina."
    elif (trafico[0:3]=="001"):
        tipoVersion="Prioritario."
    elif (trafico[0:3]=="010"):
        tipoVersion="Inmediato."
    elif (trafico[0:3]=="011"):
        tipoVersion="Relámpago."
    elif (trafico[0:3]=="100"):
        tipoVersion="Invalidación relámpago."
    elif (trafico[0:3]=="101"):
        tipoVersion="Procesando llamada critica y de emergencia"
    elif (trafico[0:3]=="110"):
        tipoVersion="Control de trabajo de Internet."
    else:
        tipoVersion="Control de red."
    #Retardo, rendimiento y fiabilidad 
    retardo="";rendimiento="";fiabilidad="";
    if (trafico[3]=="0"):
        retardo="Normal"               
    else:
        retardo="Alto"

    if (trafico[4]=="0"):
        rendimiento="Normal"
    else:
        rendimiento="Alto"

    if (trafico[5]=="0"):
        fiabilidad="Normal"
    else:
        fiabilidad="Alto"
    #Etiqueta de flujo
    etiquetaFlujo=aDecimal(binary_string[12:32])
    #Tamanio de datos
    tamanioDatos=aDecimal(datos[5:6])
    #Protocolo
    numProtocolo=aDecimal(datos[6:7])
    #Encabezado siguiente
    if(numProtocolo==1):
        encabezadoSiguiente="ICMPv4"
    elif(numProtocolo==6):
        encabezadoSiguiente="TCP"
    elif(numProtocolo==17):
        encabezadoSiguiente="UDP"
    elif(numProtocolo==58):
        encabezadoSiguiente="ICMPv6"
    elif(numProtocolo==118):
        encabezadoSiguiente="STP"
    else:
        encabezadoSiguiente="SMP"
    #Limite de salto
    limiteSalto=aDecimal(datos[7:8])
    #Direccion IP origen
    ipOrigen=ipv6(datos[8:24])
    #Direccion IP destino
    ipDestino=ipv6(datos[24:40])
    print("\t\t-Versión: ",versionDecimal)
    print("\t\t-Prioridad: ",tipoVersion)
    print("\t\t-Retardo: ",retardo)
    print("\t\t-Rendimiento: ",rendimiento)
    print("\t\t-FiabilidadL ",fiabilidad)
    print("\t\t-Etiqueta de flujo: ",etiquetaFlujo)
    print("\t\t-Tamaño de datos: ",tamanioDatos)
    print("\t\t-Encabezado siguiente: ",encabezadoSiguiente)
    print("\t\t-Límite de salto : ",limiteSalto)
    print("\t\t-Dirección origen: ",ipOrigen)
    print("\t\t-Dirección destino: ",ipDestino)
    return encabezadoSiguiente,datos[40:]
#Paquete ICMPv6
def paquete_icmpv6(encabezadoSiguiente,datos):
    icmpv6Descripcion="0";icmpv6Mensaje="";
    icmpv6Tipo=aDecimal(datos[0:1])
    icmpv6Codigo=aDecimal(datos[1:2])
    icmpv6CheckSum=':'.join(map('{:02x}'.format,datos[2:4])).upper()
    if (encabezadoSiguiente=="ICMPv6"):
        if (icmpv6Tipo==1):
            icmpv6Mensaje="Destino inalcanzable"
            if(icmpv6Codigo==0):
                icmpv6Descripcion="No existe una ruta destino"
            elif(icmpv6Codigo==1):
                icmpv6Descripcion="Comunicación con el destino administrativamente prohibida"
            elif(icmpv6Codigo==2):
                icmpv6Descripcion="No asignado"
            else:
                icmpv6Descripcion="Dirección incalcanzable"                            
        elif(icmpv6Tipo==2):
            icmpv6Mensaje="Paquete demasiado grande"
        elif(icmpv6Tipo==3):
            icmpv6Mensaje="Time exceeded message"
            if(icmpv6Codigo==0):
                icmpv6Descripcion="El límite de salto excedido"
            else:
                icmpv6Descripcion="Tiempo de reensamble de fragmento extendido"
        elif(icmpv6Tipo==4):
            icmpv6Mensaje="Problema de parámetro"
            if(icmpv6Codigo==0):
                icmpv6Descripcion="El campo del encabezado erróneo encontró"
            elif(icmpv6Codigo==1):
                icmpv6Descripcion="El tipo siguiente desconocido del encabezado encontró"
            else:
                icmpv6Descripcion="Opción desconocida del IPv6 encontrada"
        elif(icmpv6Tipo==128):
            icmpv6Mensaje="Pedido de eco"
        elif(icmpv6Tipo==129):
            icmpv6Mensaje="Respuesta de eco"
        elif(icmpv6Tipo==133):
            icmpv6Mensaje="Solicitud de router"
        elif(icmpv6Tipo==134):
            icmpv6Mensaje="Anuncio del router"
        elif(icmpv6Tipo==135):
            icmpv6Mensaje="Solicitud vecino"
        elif(icmpv6Tipo==136):
            icmpv6Mensaje="Anuncio del vecino"
        else:
            icmpv6Mensaje="Reoriente el mensaje"
    print("\t\t---------------->",encabezadoSiguiente)
    print("\t\t-Tipo: ",icmpv6Tipo)
    print("\t\t-Código: ",icmpv6Descripcion)
    print("\t\t-Mensaje: ",icmpv6Mensaje)
    print("\t\t-Checksum: ",icmpv6CheckSum)      
    return datos[4:]

#Paquete TCP/IP
def paquete_tcp(datos):
    servicio_origen="";proto_origen="";servicio_destino="";proto_destino="";
    (puerto_origen, puerto_destino, secuencia_numerica, reconocimiento_numerico, banderas_reservadas_aux) = struct.unpack('! H H L L H', datos[:14])
    aux = (banderas_reservadas_aux >> 12) *4
    bandera_urg = (banderas_reservadas_aux & 32) >> 5
    bandera_ack = (banderas_reservadas_aux & 16) >> 4
    bandera_psh = (banderas_reservadas_aux & 8) >> 3
    bandera_rst = (banderas_reservadas_aux & 4) >> 2
    bandera_syn = (banderas_reservadas_aux & 2) >> 1
    bandera_fin = banderas_reservadas_aux & 1

    if (puerto_origen==20 or puerto_destino==20):
        if (puerto_origen==20):
            servicio_origen="FTP";proto_origen="TCP";
        if (puerto_destino==20):
            servicio_destino="FTP";proto_destino="TCP";
    elif (puerto_origen==21 or puerto_destino==21):
        if (puerto_origen==21):
            servicio_origen="FTP";proto_origen="TCP";
        if (puerto_destino==21):
            servicio_destino="FTP";proto_destino="TCP";
    elif (puerto_origen==22 or puerto_destino==22):
        if (puerto_origen==22):
            servicio_origen="SSH";proto_origen="TCP";
        if (puerto_destino==22):
            servicio_destino="SSH";proto_destino="TCP";
    elif (puerto_origen==23 or puerto_destino==23):
        if (puerto_origen==23):
            servicio_origen="TELNET";proto_origen="TCP";
        if (puerto_destino==23):
            servicio_destino="TELNET";proto_destino="TCP";
    elif (puerto_origen==25 or puerto_destino==25):
        if (puerto_origen==25):
            servicio_origen="SMTO";proto_origen="TCP";
        if (puerto_destino==25):
            servicio_destino="SMTP";proto_destino="TCP";
    elif (puerto_origen==53 or puerto_destino==53):
        if (puerto_origen==53):
            servicio_origen="DNS";proto_origen="TCP/UDP";
        if (puerto_destino==53):
            servicio_destino="DNS";proto_destino="TCP/UDP";
    elif (puerto_origen==67 or puerto_destino==67):
        if (puerto_origen==67):
            servicio_origen="DHCP";proto_origen="UDP";
        if (puerto_destino==67):
            servicio_destino="DHCP";proto_destino="UDP";
    elif (puerto_origen==68 or puerto_destino==68):
        if (puerto_origen==68):
            servicio_origen="DHCP";proto_origen="UDP";
        if (puerto_destino==68):
            servicio_destino="DHCP";proto_destino="UDP";
    elif (puerto_origen==69 or puerto_destino==69):
        if (puerto_origen==69):
            servicio_origen="TFTP";proto_origen="UDP";
        if (puerto_destino==69):
            servicio_destino="TFTP";proto_destino="UDP";
    elif (puerto_origen==80 or puerto_destino==80):
        if (puerto_origen==80):
            servicio_origen="HTTP";proto_origen="TCP";
        if (puerto_destino==80):
            servicio_destino="HTTP";proto_destino="TCP";
    elif (puerto_origen==110 or puerto_destino==110):
        if (puerto_origen==110):
            servicio_origen="POP3";proto_origen="TCP";
        if (puerto_destino==110):
            servicio_destino="POP3";proto_destino="TCP";
    elif (puerto_origen==143 or puerto_destino==143):
        if (puerto_origen==143):
            servicio_origen="IMAP";proto_origen="TCP";
        if (puerto_destino==143):
            servicio_destino="IMAP";proto_destino="TCP";
    elif (puerto_origen==443 or puerto_destino==443):
        if (puerto_origen==443):
            servicio_origen="HTTPS";proto_origen="TCP";
        if (puerto_destino==443):
            servicio_destino="HTTPS";proto_destino="TCP";
    elif (puerto_origen==993 or puerto_destino==993):
        if (puerto_origen==993):
            servicio_origen="IMAPSSL";proto_origen="TCP";
        if (puerto_destino==993):
            servicio_destino="IMAPSSL";proto_destino="TCP";
    elif (puerto_origen==995 or puerto_destino==995):
        if (puerto_origen==995):
            servicio_origen="POP SSL";proto_origen="TCP";
        if (puerto_destino==995):
            servicio_destino="POP SSL";proto_destino="TCP";
        
    ventanaRecepcion=aDecimal(datos[15:17])
    checkSum=':'.join(map('{:02x}'.format,datos[17:19])).upper()
    punteroUrg=aDecimal(datos[19:20])
    print("\t\t---------------->TCP")
    if (puerto_origen>=0 and puerto_origen<=1023):
        print("\t\tPuerto Origen: Bien conocido:",puerto_origen,":",servicio_origen,":",proto_origen)
    if (puerto_destino>=0 and puerto_destino<=1023):
        print("\t\tPuerto Destino: Bien conocido:",puerto_destino,":",servicio_destino,":",proto_destino)
    if (puerto_origen>=1024 and puerto_origen<=49151):
        print("\t\tPuerto Origen: Puerto registrado")
    if (puerto_destino>=1024 and puerto_destino<=49151):
        print("\t\tPuerto Destino: Puerto registrado")
    if (puerto_origen>49151):
        print("\t\tPuerto Origen: Puerto dinámico o privado")
    if (puerto_destino>49151):
        print("\t\tPuerto Destino: Puerto dinámico o privado")
    print("\t\tNúmero de secuencia: ",secuencia_numerica)
    print("\t\tNúmero de recibo: ",reconocimiento_numerico)
    print("\t\tFlags: URG= ",bandera_urg," ACK= ",bandera_ack," PSH= ",bandera_psh," RST= ",bandera_rst," SYN= ",bandera_syn," FIN= ",bandera_fin)
    print("\t\tVentana recepción: ",ventanaRecepcion)
    print("\t\tCheckSum: ",checkSum)
    print("\t\tPuntero Urgente: ",punteroUrg)
    return servicio_origen,servicio_destino,datos[aux:]

#Paquete UDP
def paquete_udp(datos):
    servicio_origen="";servicio_destino="";proto_origen="";proto_destino="";
    puerto_origen,puerto_destino=struct.unpack('! H H',datos[:4]);
    binary_string = bin(int(binascii.hexlify(datos[4:6]), 16))[2:].zfill(8)
    longTotal=aDecimal(binary_string)
    checkSum=':'.join(map('{:02x}'.format,datos[6:8])).upper()

    if (puerto_origen==20 or puerto_destino==20):
        if (puerto_origen==20):
            servicio_origen="FTP";proto_origen="TCP";
        if (puerto_destino==20):
            servicio_destino="FTP";proto_destino="TCP";
    elif (puerto_origen==21 or puerto_destino==21):
        if (puerto_origen==21):
            servicio_origen="FTP";proto_origen="TCP";
        if (puerto_destino==21):
            servicio_destino="FTP";proto_destino="TCP";
    elif (puerto_origen==22 or puerto_destino==22):
        if (puerto_origen==22):
            servicio_origen="SSH";proto_origen="TCP";
        if (puerto_destino==22):
            servicio_destino="SSH";proto_destino="TCP";
    elif (puerto_origen==23 or puerto_destino==23):
        if (puerto_origen==23):
            servicio_origen="TELNET";proto_origen="TCP";
        if (puerto_destino==23):
            servicio_destino="TELNET";proto_destino="TCP";
    elif (puerto_origen==25 or puerto_destino==25):
        if (puerto_origen==25):
            servicio_origen="SMTO";proto_origen="TCP";
        if (puerto_destino==25):
            servicio_destino="SMTP";proto_destino="TCP";
    elif (puerto_origen==53 or puerto_destino==53):
        if (puerto_origen==53):
            servicio_origen="DNS";proto_origen="TCP/UDP";
        if (puerto_destino==53):
            servicio_destino="DNS";proto_destino="TCP/UDP";
    elif (puerto_origen==67 or puerto_destino==67):
        if (puerto_origen==67):
            servicio_origen="DHCP";proto_origen="UDP";
        if (puerto_destino==67):
            servicio_destino="DHCP";proto_destino="UDP";
    elif (puerto_origen==68 or puerto_destino==68):
        if (puerto_origen==68):
            servicio_origen="DHCP";proto_origen="UDP";
        if (puerto_destino==68):
            servicio_destino="DHCP";proto_destino="UDP";
    elif (puerto_origen==69 or puerto_destino==69):
        if (puerto_origen==69):
            servicio_origen="TFTP";proto_origen="UDP";
        if (puerto_destino==69):
            servicio_destino="TFTP";proto_destino="UDP";
    elif (puerto_origen==80 or puerto_destino==80):
        if (puerto_origen==80):
            servicio_origen="HTTP";proto_origen="TCP";
        if (puerto_destino==80):
            servicio_destino="HTTP";proto_destino="TCP";
    elif (puerto_origen==110 or puerto_destino==110):
        if (puerto_origen==110):
            servicio_origen="POP3";proto_origen="TCP";
        if (puerto_destino==110):
            servicio_destino="POP3";proto_destino="TCP";
    elif (puerto_origen==143 or puerto_destino==143):
        if (puerto_origen==143):
            servicio_origen="IMAP";proto_origen="TCP";
        if (puerto_destino==143):
            servicio_destino="IMAP";proto_destino="TCP";
    elif (puerto_origen==443 or puerto_destino==443):
        if (puerto_origen==443):
            servicio_origen="HTTPS";proto_origen="TCP";
        if (puerto_destino==443):
            servicio_destino="HTTPS";proto_destino="TCP";
    elif (puerto_origen==993 or puerto_destino==993):
        if (puerto_origen==993):
            servicio_origen="IMAPSSL";proto_origen="TCP";
        if (puerto_destino==993):
            servicio_destino="IMAPSSL";proto_destino="TCP";
    elif (puerto_origen==995 or puerto_destino==995):
        if (puerto_origen==995):
            servicio_origen="POP SSL";proto_origen="TCP";
        if (puerto_destino==995):
            servicio_destino="POP SSL";proto_destino="TCP";
    
    print("\t\t---------------->UDP")
    if (puerto_origen>=0 and puerto_origen<=1023):
        print("\t\tPuerto Origen: Bien conocido:",puerto_origen,":",servicio_origen,":",proto_origen)
    if (puerto_destino>=0 and puerto_destino<=1023):
        print("\t\tPuerto Destino: Bien conocido:",puerto_destino,":",servicio_destino,":",proto_destino)
    if (puerto_origen>=1024 and puerto_origen<=49151):
        print("\t\tPuerto Origen: Puerto registrado")
    if (puerto_destino>=1024 and puerto_destino<=49151):
        print("\t\tPuerto Destino: Puerto registrado")
    if (puerto_origen>49151):
        print("\t\tPuerto Origen: Puerto dinámico o privado")
    if (puerto_destino>49151):
        print("\t\tPuerto Destino: Puerto dinámico o privado")
    print("\t\tLongitud total = ",longTotal)
    print("\t\tChecksum = ",checkSum)
    return servicio_origen,servicio_destino,datos[8:]

#Segmento DNS
def paquete_dns(datos):
    codigo_op="";codigo_r="";
    binary_string = bin(int(binascii.hexlify(datos[2:4]), 16))[2:].zfill(8)
    identificador=':'.join(map('{:02x}'.format,datos[0:2])).upper()
    #BANDERAS
    flag_QR=binary_string[:1]
    OpCode=aDecimal(binary_string[1:5])
    if (OpCode==0):
        codigo_op="Constula estándar"
    elif (OpCode==1):
        codigo_op="Constula inversa"
    else:
        codigo_op+"Solicitud del estado del servidor"
    flag_AA=binary_string[5:6]
    flag_TC=binary_string[6:7]
    flag_RD=binary_string[7:8]
    flag_RA=binary_string[8:9]
    flag_Z=binary_string[9:10]
    flag_AD=binary_string[10:11]
    flag_CD=binary_string[11:12]
    RCode=aDecimal(binary_string[12:16])
    if (RCode==0):
        codigo_r="Ningún error"
    elif (RCode==1):
        codigo_r="Error de formato"
    elif (RCode==2):
        codigo_r="Fallo en el servidor"
    elif (RCode==3):
        codigo_r="Error en nombre"
    elif (RCode==4):
        codigo_r="No implementado"
    else:
        codigo_r="Rechazado"
    #CONTADORES
    binary_string = bin(int(binascii.hexlify(datos[4:6]), 16))[2:].zfill(8)
    QDcount=aDecimal(binary_string[0:16])
    binary_string = bin(int(binascii.hexlify(datos[6:8]), 16))[2:].zfill(8)
    ANcount=aDecimal(binary_string[0:16])
    binary_string = bin(int(binascii.hexlify(datos[8:10]), 16))[2:].zfill(8)
    NScount=aDecimal(binary_string[0:16])
    binary_string = bin(int(binascii.hexlify(datos[10:12]), 16))[2:].zfill(8)
    ARcount=aDecimal(binary_string[0:16])
    #Campo pregunta
    print("\t\t--------------->DNS")
    print("\t\tID: ",identificador)
    print("\t\tQR = ",flag_QR,"AA =",flag_AA,"TC = ",flag_TC,"RD = ",flag_RD,"\n\t\tRA = ",flag_RA,"Z =",flag_Z,"AD = ",flag_AD,"CD = ",flag_CD)
    print("\t\tCódigo OP: ",OpCode,":",codigo_op)
    print("\t\tCódigo R: ",RCode,":",codigo_r)
    print("\t\tQDcount =",QDcount,"ANcount = ",ANcount,"NScount = ",NScount,"ARcount",ARcount) 
    print("\t\tDominios de pregunta: ")
    valor=12
    for x in range (QDcount):
        nombreP=""
        rango=int(datos[valor])
        while(rango!=0):
            j=0
            while(j<rango):
                valor+=1
                j+=1
                nombreP+=chr(datos[valor])
            nombreP+='.'
            valor+=1
            rango=int(datos[valor])
        print("\t\t-",nombreP)
        cadena_bits_tipoP=bin(int(binascii.hexlify(datos[valor+1:valor+3]), 16))[2:].zfill(8)
        tipoP=aDecimal(cadena_bits_tipoP)
        if (tipoP==1):
            print("\t\t\t-Tipo: A")
        elif (tipoP==5):
            print("\t\t\t-Tipo: CNAME")
        elif (tipoP==13):
            print("\t\t\t-Tipo: HINFO")
        elif (tipoP==15):
            print("\t\t\t-Tipo: MX")
        elif (tipoP==22):
            print("\t\t\t-Tipo: NS")
        elif (tipoP==6):
            print("\t\t\t-Tipo: SOA")
        elif (tipoP==12):
            print("\t\t\t-Tipo: PTR")
        else:
            print("\t\t\t-Tipo: ",tipoP)

        cadena_bits_claseP=bin(int(binascii.hexlify(datos[valor+3:valor+5]), 16))[2:].zfill(8)
        claseP=aDecimal(cadena_bits_claseP)
        if (claseP==0):
            print("\t\t\t-Clase: Reservada")
        elif (claseP==1):
            print("\t\t\t-Clase: IN, Internet")
        elif (claseP==3):
            print("\t\t\t-Clase: CH, Chaos")
        elif (claseP==4):
            print("\t\t\t-Clase: HS, Hesiod")
        elif (claseP==254):
            print("\t\t\t-Clase: None")
        elif (claseP==255):
            print("\t\t\t-Clase: Any")
        elif (claseP>=65280 and claseP<=65534):
            print("\t\t\t-Clase: Uso privado")
        else:
            print("\t\t\t-Desconocido")
        valor+=4
    print("\t\tDominios de respuesta:")
    for x in range (ANcount):
        nombreA=nombreP
        print("\t\t-",nombreA)
        cadena_bits_tipoA=bin(int(binascii.hexlify(datos[valor+1:valor+3]), 16))[2:].zfill(8)
        tipoA=aDecimal(cadena_bits_tipoA)
        if (tipoA==1):
            print("\t\t\t-Tipo: A")
        elif (tipoA==5):
            print("\t\t\t-Tipo: CNAME")
        elif (tipoA==13):
            print("\t\t\t-Tipo: HINFO")
        elif (tipoA==15):
            print("\t\t\t-Tipo: MX")
        elif (tipoA==22):
            print("\t\t\t-Tipo: NS")
        elif (tipoA==6):
            print("\t\t\t-Tipo: SOA")
        elif (tipoA==12):
            print("\t\t\t-Tipo: PTR")
        else:
            print("\t\t\t-Tipo: ",tipoA)

        cadena_bits_claseA=bin(int(binascii.hexlify(datos[valor+3:valor+5]), 16))[2:].zfill(8)
        claseA=aDecimal(cadena_bits_claseA)
        if (claseA==0):
            print("\t\t\t-Clase: Reservada")
        elif (claseA==1):
            print("\t\t\t-Clase: IN, Internet")
        elif (claseA==3):
            print("\t\t\t-Clase: CH, Chaos")
        elif (claseA==4):
            print("\t\t\t-Clase: HS, Hesiod")
        elif (claseA==254):
            print("\t\t\t-Clase: None")
        elif (claseA==255):
            print("\t\t\t-Clase: Any")
        elif (claseA>=65280 and claseA<=65534):
            print("\t\t\t-Clase: Uso privado")
        else:
            print("\t\t\t-Desconocido")
        cadena_bits_ttl=bin(int(binascii.hexlify(datos[valor+5:valor+9]), 16))[2:].zfill(8)
        ttl=aDecimal(cadena_bits_ttl)
        print("\t\t\t-TTL = ",ttl)
        cadena_bits_rlen=bin(int(binascii.hexlify(datos[valor+9:valor+11]), 16))[2:].zfill(8)
        Rlen=aDecimal(cadena_bits_rlen)
        print("\t\t\t-Rlen = ",Rlen)
        if (tipoA==1):
            Rdata=ipv4(struct.unpack('! 4s',datos[valor+11:valor+15]))
        elif (tipoA==5):
            Rdata=nombreP
        elif (tipoA==15):
            Rdata=int(datos[valor+11:valor+13])
        elif (tipoA==22):
            Rdata=datos[valor+11:Rlen]
        elif (tipoA==6):
            Rdata=datos[valor+11:valor+15]
        elif (tipoA==12):
            Rdata=nombreP
        else:
            Rdata=datos[valor+11:Rlen]
        print("\t\t\t-Rdata: ",Rdata)
        valor+=14
    return datos[valor:]

#Convertir a decimal
def aDecimal(binary_string):
    decimal=0
    exp=len(binary_string)-1
    for i in binary_string:
        decimal+=(int(i)*2**(exp))
        exp=exp-1
    return decimal
#Cosnvertir a Hexadecimal
def dec_to(num, sistema = 2):
  valores_hexa = {10:'A', 11:'B', 12:'C', 13:'D', 14:'E', 15:'F'}
  if (num==0):
      return 0
  if (sistema > 1 and sistema < 17):
    valor_ret = []
    while num:
      num, residuo = divmod(num, sistema)
      valor_ret.append(valores_hexa[residuo]) if (residuo > 9) else valor_ret.append(str(residuo))
    return ''.join(valor_ret[::-1])
  return 'Verifica que el sistema al que deseas convertir sea válido'

#Correr el programa
main()
