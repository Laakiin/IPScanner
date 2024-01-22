import netifaces
from pythonping import ping
import concurrent.futures
from tkinter import messagebox
import tkinter as tk
from tkinter import ttk
import socket
from scapy.all import ARP, Ether, srp
import tkinter.font as tkFont

ver="1.0"

def ping_ip(ip):
    try:
        # Envoie un seul paquet ICMP Echo Request (ping)
        response = ping(ip, count=1, timeout=2)
        return response._responses[0].success
    except Exception as e:
        print(f"Erreur lors du ping : {e}")
        return False


def scan_ips(ip_list):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Utilise la fonction ping_ip pour pinger chaque adresse IP en parallèle
        results = list(executor.map(ping_ip, ip_list))

    ipup = []
    hostname = []
    mac = []
    for ip, resultat in zip(ip_list, results):
        if resultat:
            ipup.append(ip)
            hostname.append(get_hostname(ip))
            mac.append(get_mac_address(ip))


    return ipup, hostname, mac

def create_ip_list(net_ip,start,end):
    ip_list = []
    net_ip = net_ip[:-1]
    for i in range(start,end):
        ip_list.append(net_ip + str(i))
    return ip_list


def get_mac_address(ip):
    try:
        # Créer une requête ARP pour obtenir l'adresse MAC associée à l'adresse IP
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast Ethernet frame
        packet = ether/arp_request

        # Envoyer la requête ARP et recevoir la réponse
        result = srp(packet, timeout=3, verbose=0)[0]

        # Extraire l'adresse MAC de la réponse
        mac_address = result[0][1].hwsrc
        return mac_address
    except Exception as e:
        print(f"Erreur lors de la récupération de l'adresse MAC : {str(e)}")
        return None

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def get_local_ip_and_mask():
    try:
        # Obtient le nom de l'interface par défaut (interface connectée à Internet)
        default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]

        # Obtient l'adresse IP de l'interface par défaut
        ip_address = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]['addr']

        # Obtient le masque de sous-réseau de l'interface par défaut
        netmask = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]['netmask']

        return ip_address, netmask
    except (KeyError, ValueError, OSError) as e:
        print(f"Erreur lors de la récupération de l'adresse IP et du masque : {e}")
        return None, None

def create_ip_list_from_local_ip():
    ip_list = []
    ip, masque = get_local_ip_and_mask()
    ##separate ip in 4 parts
    ip=ip.split(".")
    if masque=="255.255.255.0":
        for i in range(1,255):
            ip_list.append(ip[0]+"."+ip[1]+"."+ip[2]+"."+str(i))
    elif masque=="255.255.0.0":
        for i in range(1,255):
            for j in range(1,255):
                ip_list.append(ip[0]+"."+ip[1]+"."+str(i)+"."+str(j))
    elif masque=="255.0.0.0":
        for i in range(1,255):
            for j in range(1,255):
                for k in range(1,255):
                    ip_list.append(ip[0]+"."+str(i)+"."+str(j)+"."+str(k))
    return ip_list



class IPScannerApp(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.selected_item = None
        self.event = None
        self.title("IP Scanner")
        self.geometry("400x300")
        self.resizable(False, True)

        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        menu_bar.add_cascade(label="Run", command=self.run)
        menu_bar.add_command(label="About", command=self.about)

        self.tree = ttk.Treeview(self, columns=("IP", "Hostname", "MAC"), show="headings")
        self.tree.heading("IP", text="IP")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("MAC", text="MAC")

        self.tree.column("IP", width=125)
        self.tree.column("Hostname", width=125)
        self.tree.column("MAC", width=150)

        # Configurer la taille de la police pour les éléments
        item_font = tkFont.Font(family="Arial", size=12)
        self.tree.tag_configure("mytag", font=item_font)

        # Configurer la taille de la police pour les en-têtes de colonnes
        header_font = tkFont.Font(family="Arial", size=14, weight="bold")
        style = ttk.Style()
        style.configure("Treeview.Heading", font=header_font)

        for col in self.tree["columns"]:
            self.tree.heading(col, text=col, anchor="w")
            self.tree.column(col, anchor="w")

        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<<TreeviewSelect>>", self.on_treeview_select)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copier", command=self.copy_selected)

        self.tree.bind("<Button-3>", self.show_context_menu)

    def run(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        ip_list = create_ip_list_from_local_ip()
        ipup, hostname, mac = scan_ips(ip_list)
        for i in range(len(ipup)):
            self.tree.insert("", "end", values=(ipup[i], hostname[i], mac[i]), tags=("mytag",))

    def about(self):
        tk.messagebox.showinfo("About", f"This software was created by Laakiin\nCurrently in v{ver}\nSource code available on GitHub: not yet")

    def on_treeview_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            self.selected_item = selected_item

    def show_context_menu(self, event):
        if self.selected_item:
            self.event = event
            self.context_menu.post(event.x_root, event.y_root)

    def copy_selected(self):
        if self.selected_item and self.event:
            selected_item = self.selected_item[0]
            selected_column = self.tree.identify_column(self.event.x)
            selected_values = self.tree.item(selected_item, "values")

            if selected_column == "#1":
                value_to_copy = selected_values[0]
            elif selected_column == "#2":
                value_to_copy = selected_values[1]
            elif selected_column == "#3":
                value_to_copy = selected_values[2]

            self.clipboard_clear()
            self.clipboard_append(value_to_copy)
            self.update()




# Press the green button in the gutter to run the script.
if __name__ == "__main__":
    app = IPScannerApp()
    app.mainloop()

