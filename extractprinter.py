#Script que realiza a extracao e conversao de arquivos impressos via rede, capturados em arquivos pcap.
#Testado no Kali Linux

#Apresentado no Livro Guerrilha Cibernética

#www.peritocibernetico.com.br
#www.guerrilhacibernetica.com.br

#Este software exige a instalacao do GhostScript e do GhostPCL para a conversao
#dos arquivos capturados para o formato PDF.
#Ghostscript pode ser instalado via apt-get.
#O binario para manipular PCL pode ser baixado no seguinte link:
#https://ghostscript.com/releases/gpcldnld.html

#Trocar as variaveis se necessario, principalmente o nome do arquivo pcap que sera lido (nomearquivo)


import subprocess
import sys
import binascii
import os

nomearquivo = "printer4.pcap"
pathpcl = "/home/kali/Documents/guerrilha/printer/ghostpcl-10.0.0-linux-x86_64/gpcl6-1000-linux-x86_64"

print("Script criado por Gabriel Nunes - Perito Cibernetico")
print("Extracao e Conversao de arquivos impressos via rede, capturados em arquivos no formato PCAP")

tshark = subprocess.getoutput("tshark -r {} -Y 'tcp.port == 9100' -T fields -e tcp.stream | sort -u | grep -v 'Running'".format(nomearquivo))


streams = tshark.split('\n')

for i in streams:
    if 'Running' in i:
        continue
    
    raw = subprocess.getoutput("tshark -r {} -q -z follow,tcp,raw,{}".format(nomearquivo,i))
    ind = raw.find('Node 1:')
    ind2 = raw.find('\n',ind)
    indfinal = raw.find('=====',ind)
    arquivo = raw[ind2+1:indfinal-1]
    
    try:
        arquivobin = binascii.unhexlify(arquivo.replace('\n','').strip())
    except:
        continue

    if len(arquivobin) == 0:
        continue

    arquivoascii = binascii.a2b_hex(arquivo.replace('\n','').strip()).decode('latin-1')
    indlin = arquivoascii.find('PJL ENTER LANGUAGE')
    indlinfinal = arquivoascii.find('\n',indlin)
    linguagem = arquivoascii[indlin:indlinfinal]

    if indlin != -1:
        with open("raw_"+i+".pcl","wb") as f:
            f.write(arquivobin)
            print("Salvou arquivo raw_{}.pcl".format(i))
    else:
        continue

    
    if 'PCLXL' in linguagem:
        nomesaida = "raw_" + i
        pcl = subprocess.getoutput("{} -dNOPAUSE -sDEVICE=pdfwrite -sOutputFile={}.pdf {}.pcl".format(pathpcl,nomesaida,nomesaida))
        if os.path.isfile(nomesaida+".pdf"):
            print("Arquivo {}.pdf criado".format(nomesaida))
    if 'Postscript' in linguagem:
        nomesaida = "raw_" + i
        ps = subprocess.getoutput("gs -dNOPAUSE -dBATCH -dSAFER -dProcessColorModel=/DeviceRGB -dPDFSETTINGS=/default -dCompatibilityLevel=1.4 -dPDFX=false -dDEVICEWIDTHPOINTS=612 -dDEVICEHEIGHTPOINTS=792 -sDEVICE=pdfwrite -sOutputFile={}.pdf -q -f {}.pcl".format(nomesaida,nomesaida))

        if os.path.isfile(nomesaida+".pdf"):
            print("Arquivo {}.pdf criado".format(nomesaida))
        
