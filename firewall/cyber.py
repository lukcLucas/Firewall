import socket
import struct
import sys

def main():
    # Obtém o endereço IP do host onde o script está rodando
    HOST = socket.gethostbyname(socket.gethostname())

    # Tenta criar um socket RAW, que é capaz de capturar pacotes em nível de rede
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    # Loop infinito para ler pacotes recebidos pelo socket
    while True:
        # Recebe pacotes
        packet, addr = s.recvfrom(65565)
        
        # Desempacota o cabeçalho IP do pacote recebido (primeiros 20 bytes)
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Extrai endereços IP de origem e destino do cabeçalho
        src_addr = socket.inet_ntoa(iph[8])
        dst_addr = socket.inet_ntoa(iph[9])

        # Checa se o pacote está destinado ao IP do Pi-hole
        if dst_addr == '192.168.1.5':  # Substitua '192.168.1.5' pelo IP real do Pi-hole, se necessário
            # Se o pacote é destinado ao Pi-hole, permita e registre a ação
            print('Permitindo tráfego para o Pi-hole de', src_addr)
            # Aqui, você poderia implementar regras adicionais, como filtragem de portas
        
        else:
            # Se não for destinado ao Pi-hole, o tráfego é bloqueado e isso é registrado
            print('Bloqueando tráfego de', src_addr, 'para', dst_addr)


        if dst_addr == '192.168.1.5' and src_addr.startswith('192.168.1.'):
            print('Permitindo tráfego interno para o Pi-hole de', src_addr)
        else:
            print('Bloqueando tráfego de', src_addr, 'para', dst_addr)

        # Permitir sempre o tráfego dentro da rede local
        if src_addr.startswith('192.168.1.') and dst_addr.startswith('192.168.1.'):
           print('Permitindo tráfego de rede local de', src_addr, 'para', dst_addr)
        elif dst_addr == '192.168.1.5':  # Apenas para o Pi-hole
           print('Permitindo tráfego para o Pi-hole de', src_addr)
        else:
           print('Bloqueando tráfego de', src_addr, 'para', dst_addr)



if __name__ == '__main__':
    main()
