#!/usr/bin/python3
"""
Graphical user interface to visualize the functionality of the protocol.
"""

from tkinter import *
from tkinter import ttk
import pickle
import os

import config
config.EVAL = False  # Disable eval flag for GUI demo

import protocol
from helpers import get_random_bytes, trans_to_string
import random
import ipaddress


cur_peer = 0


def get_peer() -> protocol.Peer:
    global cur_peer
    cur_peer += 1
    return peers[cur_peer - 1]


def update_list() -> None:
    """Update the list of addresses with funds"""
    with open(working_dir + '/peers.pyc', 'wb') as fd:
        pickle.dump(peers, fd)


def command_send_ad() -> None:
    """Create a new peer advertisement from the information of the
    textfields advertise it
        e.g write it into the blockchain.
    """

    p = next((p for p in peers if p.public_key_hash() == bytes(
        bytearray.fromhex(var_pubkey.get()))), None)
    if p is None:
        raise ValueError('There is no peer with this public key!')

    # Update all values except for public key
    p.ip_address = ipaddress.ip_address(var_ip.get())
    p.port = int(var_port.get())
    p.protocols = bytes(bytearray.fromhex(var_peer_service.get()))

    # Write into blockchain
    p.advertise(s)

    var_ip.set('')
    var_port.set('')
    var_pubkey.set('')
    var_peer_service.set('')
    var_cont_tx.set('')


def command_send_request() -> None:
    """Create a new user request and write it into the blockchain."""
    service = bytes(bytearray.fromhex(var_user_service.get()))
    net_size = int(var_user_netsize.get())
    user_size = int(var_user_usersize.get())
    capabilities = bytes(bytearray.fromhex(var_user_capabilities.get()))
    nonce = bytes(bytearray.fromhex(var_user_nonce.get()))

    u = protocol.User(
        service,
        net_size,
        user_size,
        capabilities,
        nonce,
    )

    u.request(s)

    var_user_service.set('')
    var_user_nonce.set('')


def command_random_request() -> None:
    """Generate a random user request and fill the text fields accordingly."""
    var_user_netsize .set('10')
    var_user_usersize .set('100')
    var_user_service.set('0001')
    var_user_capabilities.set('00' * protocol.UserRequest.LAYOUT['capabilities'])
    var_user_nonce.set(get_random_bytes(protocol.UserRequest.LAYOUT['nonce']).hex())


def command_get_peer() -> None:
    """Generate a random peer ad and fill the text fields accordingly."""
    p = get_peer()
    var_ip.set(str(p.ip_address))
    var_port.set(str(p.port))
    var_pubkey.set(p.public_key_hash().hex())
    var_peer_service.set(p.service.hex())
    var_cont_tx.set(trans_to_string(p.cont_tx))


def command_update() -> None:
    """
    Update all the information by using the information from all newly mined
    blocks.
    I.E. Update the displayed peers, requests and networks.

    Called by update button
    :return:
    None
    """
    # Update state with all new blocks added since last update
    s.update()

    # Update Block Label
    var_block.set('Block: ' + str(s.current_block))

    # Update Expiration Label
    # var_expiration_height.set("Expiration Height: " + str(
    #    protocol._calc_expiration_height(s.current_block, s.TIMEOUT)))

    # Update Peers
    peer_entries = peer_tree.get_children('')
    for e in peer_entries:
        # Remove outdated peers
        if e not in s.peers:
            peer_tree.delete(e)
    # Add new Peers
    for k, v in s.peers.items():
        update_peer(k, v)

    # Update Requests
    request_entries = list(user_tree.get_children(''))
    for i, pending in enumerate(s.pending_requests):
        id_gen = str(hash(pending)) + str(hash(i))
        if id_gen in request_entries:
            request_entries.remove(id_gen)
    for outdated in request_entries:
        user_tree.delete(outdated)

    for i, r in enumerate(s.pending_requests):
        update_request(i, r)

    # Update Networks
    network_entries = list(network_tree.get_children(''))
    for i, net in enumerate(s.networks):
        id_gen = str(hash(net)) + str(hash(i))
        if id_gen in network_entries:
            network_entries.remove(id_gen)
    for outdated in network_entries:
        network_tree.delete(outdated)

    for i, r in enumerate(s.networks):
        update_network(i, r)


def command_generate() -> None:
    """Generate as many blocks as defined in the text field."""
    try:
        amount = int(var_generate_count.get())
    except ValueError:
        var_generate_count.set('1')
        return
    s.generate(amount)
    # Store changes
    update_list()


def command_quit() -> None:
    root.destroy()


def update_peer(name: str, peer: protocol.PeerInfo) -> None:
    """Add the peer to the peer tree if it is not present yet."""
    id_adr = name + ':adr'
    id_pro = name + ':pro'
    id_con = name + ':con'
    id_blo = name + ':blo'
    id_fun = name + ':fun'
    id_total_counts = name + ':tct'
    id_con_counts = name + ':cct'
    peer_entries = peer_tree.get_children('')

    if name not in peer_entries:
        peer_tree.insert('', 'end', name, text=name)
        peer_tree.insert(name, 'end', id_adr)
        peer_tree.insert(name, 'end', id_pro)
        peer_tree.insert(name, 'end', id_con)
        peer_tree.insert(name, 'end', id_blo)
        peer_tree.insert(name, 'end', id_fun)
        peer_tree.insert(name, 'end', id_total_counts)
        peer_tree.insert(name, 'end', id_con_counts)

    peer_tree.item(
        id_adr, text='Address: ' + str(peer.address) + ':' + str(peer.port))
    peer_tree.item(id_pro, text='Service: 0x' + peer.service.hex())
    peer_tree.item(id_con, text='Cont_TX: ' + trans_to_string(peer.cont_tx))
    peer_tree.item(id_blo, text='Block: ' + str(peer.block))
    p = next((p for p in peers if
              p.public_key_hash() == bytes(bytearray.fromhex(name))), None)
    if p is not None:
        peer_tree.item(id_fun,
                       text='Avail. Funds: ' + str(p.get_available_funds()))
    peer_tree.item(id_total_counts,
                   text='Total Ads: ' + str(s.times_seen[peer.pubkey.hex()]))
    peer_tree.item(id_con_counts, text='Consecutive Ads: ' + str(
        s.consecutive_seen[peer.pubkey.hex()]))


def update_request(index: int, request: protocol.UserInfo) -> None:
    """Add the specified user if it does not exist yet."""
    id_gen = str(hash(request)) + str(hash(index))
    id_net = id_gen + ':net'
    id_usr = id_gen + ':usr'
    id_joi = id_gen + ':joi'
    id_pro = id_gen + ':pro'
    id_par = id_gen + ':par'
    id_non = id_gen + ':non'
    id_blo = id_gen + ':blo'
    user_entries = user_tree.get_children('')

    if id_gen not in user_entries:
        user_tree.insert('', 'end', id_gen, text=index)
        user_tree.insert(id_gen, 'end', id_net)
        user_tree.insert(id_gen, 'end', id_usr)
        user_tree.insert(id_gen, 'end', id_pro)
        user_tree.insert(id_gen, 'end', id_joi)
        user_tree.insert(id_gen, 'end', id_par)
        user_tree.insert(id_gen, 'end', id_non)
        user_tree.insert(id_gen, 'end', id_blo)

    joining = 'True' if request.joining else 'False'

    user_tree.item(id_gen)['text'] = index
    user_tree.item(id_net, text='Net size: ' + str(request.network_size))
    user_tree.item(id_usr, text='User size: ' + str(request.user_size))
    user_tree.item(id_joi, text='Joining: ' + joining)
    user_tree.item(id_pro, text='Protocol: 0x' + request.protocol.hex())
    user_tree.item(id_par, text='Parameters: 0x' + request.parameters.hex())
    user_tree.item(id_non, text='Nonce: ' + request.nonce.hex())
    user_tree.item(id_blo, text='Block: ' + str(request.block))


def update_network(index: int, network: protocol.Network) -> None:
    """Add network if not yet present."""
    # NOTE: Does not (yet) update peer list, but that should not change
    id_gen = str(hash(network)) + str(hash(index))
    id_nsi = id_gen + ':nsi'
    id_usi = id_gen + ':usi'
    id_pro = id_gen + ':pro'
    id_par = id_gen + ':par'
    id_cre = id_gen + ':cre'
    id_pee = id_gen + ':pee'
    id_usr = id_gen + ':usr'
    network_entries = network_tree.get_children('')

    if id_gen not in network_entries:
        network_tree.insert('', 'end', id_gen, text=index)
        network_tree.insert(id_gen, 'end', id_nsi)
        network_tree.insert(id_gen, 'end', id_usi)
        network_tree.insert(id_gen, 'end', id_pro)
        network_tree.insert(id_gen, 'end', id_par)
        network_tree.insert(id_gen, 'end', id_cre)
        network_tree.insert(id_gen, 'end', id_pee, text='Peers')
        # Add peers
        for p in network.peers:
            network_tree.insert(id_pee, 'end', id_gen + p.hex(), text=p.hex())

            peer = next((peer for peer in peers if
                         peer.public_key_hash() == bytes(
                             bytearray.fromhex(p.hex()))), None)
            if peer is not None:
                network_tree.insert(id_gen + p.hex(), 'end',
                                    id_gen + p.hex() + ':adr',
                                    text='Address: ' + str(
                                        peer.ip_address) + ':' + str(
                                        peer.port))
                network_tree.insert(id_gen + p.hex(), 'end',
                                    id_gen + p.hex() + ':proto',
                                    text='Protocol(s): 0x' +
                                         peer.protocols.hex())
                network_tree.insert(id_gen + p.hex(), 'end',
                                    id_gen + p.hex() + ':con',
                                    text='Cont_TX: ' + trans_to_string(
                                        peer.cont_tx))
                network_tree.insert(id_gen + p.hex(), 'end',
                                    id_gen + p.hex() + ':fun',
                                    text='Avail. Funds: ' + str(
                                        peer.get_available_funds()))
        # Add Users --> Only extended mode
        if not protocol.BASIC_MODE:
            network_tree.insert(id_gen, 'end', id_usr, text='Users')
            for u in network.users:
                joining = 'True' if u.joining else 'False'

                network_tree.insert(id_usr, 'end', id_usr + u.nonce.hex(),
                                    text=u.nonce.hex())

                network_tree.insert(id_usr + u.nonce.hex(), 'end',
                                    id_usr + u.nonce.hex() + ':net',
                                    text='Net size: ' + str(u.network_size))
                network_tree.insert(id_usr + u.nonce.hex(), 'end',
                                    id_usr + u.nonce.hex() + ':usr',
                                    text='User size: ' + str(u.user_size))
                network_tree.insert(id_usr + u.nonce.hex(), 'end',
                                    id_usr + u.nonce.hex() + ':joi',
                                    text='Joining: ' + joining)
                network_tree.insert(id_usr + u.nonce.hex(), 'end',
                                    id_usr + u.nonce.hex() + ':pro',
                                    text='Protocol: 0x' + u.protocol.hex())
                network_tree.insert(id_usr + u.nonce.hex(), 'end',
                                    id_usr + u.nonce.hex() + ':par',
                                    text='Parameters: 0x' + u.parameters.hex())
                network_tree.insert(id_usr + u.nonce.hex(), 'end',
                                    id_usr + u.nonce.hex() + ':non',
                                    text='Nonce: ' + u.nonce.hex())
                network_tree.insert(id_usr + u.nonce.hex(), 'end',
                                    id_usr + u.nonce.hex() + ':blo',
                                    text='Block: ' + str(u.block))

    network_tree.item(id_gen)['text'] = index
    network_tree.item(id_nsi, text='Net size: ' + str(network.get_net_size()))
    network_tree.item(id_usi,
                      text='User size: ' + str(network.get_user_size()))
    network_tree.item(id_pro, text='Protocol: 0x' + network.protocol.hex())
    network_tree.item(id_par, text='Parameters: 0x' + network.parameters.hex())
    network_tree.item(id_cre, text='Creation: ' + str(network.creation))


# Define root object of the graphical interface
root = Tk()

# Define 3 subframes for controls
frame_control_peers = ttk.Frame(root, borderwidth=1, relief='ridge')
frame_control_users = ttk.Frame(root, borderwidth=1, relief='ridge')
frame_control_general = ttk.Frame(root, borderwidth=1, relief='ridge')

# Define 3 subframes for the information
frame_info_peers = ttk.Frame(root)
frame_info_users = ttk.Frame(root)
frame_info_networks = ttk.Frame(root)

# Add control subframes as first row
frame_control_peers.grid(column=0, row=0, sticky=(N, S, W, E))
frame_control_users.grid(column=1, row=0, sticky=(N, S, W, E))
frame_control_general.grid(column=2, row=0, sticky=(N, S, W, E))

# Add info subframes as second row
frame_info_peers.grid(column=0, row=1, sticky=(N, S, W, E))
frame_info_users.grid(column=1, row=1, sticky=(N, S, W, E))
frame_info_networks.grid(column=2, row=1, sticky=(N, S, W, E))

# Create variable for text fields
var_ip = StringVar()
var_port = StringVar()
var_pubkey = StringVar()
var_peer_service = StringVar()
var_cont_tx = StringVar()

# Create text fields
entry_ip = ttk.Entry(frame_control_peers, textvariable=var_ip)
entry_port = ttk.Entry(frame_control_peers, textvariable=var_port)
entry_pubkey = ttk.Entry(frame_control_peers, textvariable=var_pubkey)
entry_pubkey.configure(state='readonly')
entry_peer_service = ttk.Entry(frame_control_peers, textvariable=var_peer_service)
entry_cont_tx = ttk.Entry(frame_control_peers, textvariable=var_cont_tx)
entry_cont_tx.configure(state='readonly')

# Create labels
label_ip = ttk.Label(frame_control_peers, text='IP')
label_port = ttk.Label(frame_control_peers, text='Port')
label_pubkey = ttk.Label(frame_control_peers, text='PubKey')
label_peer_service = ttk.Label(frame_control_peers, text='Capabilities')
label_cont_tx = ttk.Label(frame_control_peers, text='Cont_TX')

# Define buttons
button_send_peer = ttk.Button(
    frame_control_peers,
    text='Send Peer Ad',
    command=command_send_ad
)
button_random_peer = ttk.Button(
    frame_control_peers,
    text='Get Peer',
    command=command_get_peer
)

# Add textfields to frame
entry_ip.grid(column=1, row=0)
entry_port.grid(column=1, row=1)
entry_pubkey.grid(column=1, row=2)
entry_peer_service.grid(column=1, row=3)
entry_cont_tx.grid(column=1, row=4)

# Add labels to frame
label_ip.grid(column=0, row=0, sticky=W)
label_port.grid(column=0, row=1, sticky=W)
label_pubkey.grid(column=0, row=2, sticky=W)
label_peer_service.grid(column=0, row=3, sticky=W)
label_cont_tx.grid(column=0, row=4, sticky=W)

# Add buttons to frame
# button_get_peer.grid(column=2, row=2)
button_random_peer.grid(column=2, row=3, sticky=(S, E))
button_send_peer.grid(column=2, row=4, sticky=(S, E))

# Create variable for text fields
var_user_netsize = StringVar()
var_user_usersize = StringVar()
var_user_service = StringVar()
var_user_capabilities = StringVar()
var_user_nonce = StringVar()

# Create text fields
entry_user_netsize = ttk.Entry(
    frame_control_users, textvariable=var_user_netsize)
entry_user_usersize = ttk.Entry(
    frame_control_users, textvariable=var_user_usersize)
entry_user_protocol = ttk.Entry(
    frame_control_users, textvariable=var_user_service)
entry_user_parameters = ttk.Entry(
    frame_control_users, textvariable=var_user_capabilities)
entry_user_nonce = ttk.Entry(frame_control_users, textvariable=var_user_nonce)
entry_user_nonce.configure(state='readonly')

# Create Radiobutton
check_joining_state = BooleanVar()
check_joining = ttk.Checkbutton(frame_control_users, text='Joining?',
                                variable=check_joining_state)

# Create labels
label_user_netsize = ttk.Label(frame_control_users, text='Net Size')
label_user_usersize = ttk.Label(frame_control_users, text='User Size')
label_user_protocol = ttk.Label(frame_control_users, text='Protocol')
label_user_parameters = ttk.Label(frame_control_users, text='Parameters')
label_user_nonce = ttk.Label(frame_control_users, text='Nonce')

# Add textfields to frame
entry_user_netsize.grid(column=1, row=0)
entry_user_usersize.grid(column=1, row=1)
entry_user_protocol.grid(column=1, row=2)
entry_user_parameters.grid(column=1, row=3)
entry_user_nonce.grid(column=1, row=4)

# Add labels to frame
label_user_netsize.grid(column=0, row=0, sticky=W)
label_user_usersize.grid(column=0, row=1, sticky=W)
label_user_protocol.grid(column=0, row=2, sticky=W)
label_user_parameters.grid(column=0, row=3, sticky=W)
label_user_nonce.grid(column=0, row=4, sticky=W)

# Create Peer buttons
button_random_peer = ttk.Button(
    frame_control_users, text='Random Request', command=command_random_request)
button_send_user = ttk.Button(
    frame_control_users, text='Send User Req', command=command_send_request)

# Add buttoms to frame
check_joining.grid(column=2, row=2)
button_random_peer.grid(column=2, row=3)
button_send_user.grid(column=2, row=4)

# Create variable for text fields
var_block = StringVar()

# Create tree for peer information
peer_tree = ttk.Treeview(frame_info_peers)
peer_tree.item('', open=TRUE)
peer_tree.heading('#0', text='Peers')

# Create tree for User requests
user_tree = ttk.Treeview(frame_info_users)
user_tree.heading('#0', text='Pending Requests')

# Create tree to show Networks
network_tree = ttk.Treeview(frame_info_networks)
network_tree.heading('#0', text='Networks')

# Add all 3 trees to the frame
peer_tree.grid(column=0, row=0, sticky=(W, E, S, N))
user_tree.grid(column=0, row=0, sticky=(W, E, S, N))
network_tree.grid(column=0, row=0, sticky=(W, E, S, N))

# All rows and columns have same weight
frame_info_peers.columnconfigure(0, weight=1)
frame_info_peers.rowconfigure(0, weight=1)
frame_info_users.columnconfigure(0, weight=1)
frame_info_users.rowconfigure(0, weight=1)
frame_info_networks.columnconfigure(0, weight=1)
frame_info_networks.rowconfigure(0, weight=1)

# Generate content of general frame
var_generate_count = StringVar()
var_generate_count.set(1)
entry_generate_count = ttk.Entry(
    frame_control_general,
    textvariable=var_generate_count
)

# Generate general buttons
button_update = ttk.Button(
    frame_control_general,
    text='Update',
    command=command_update
)
button_generate = ttk.Button(
    frame_control_general,
    text='Generate',
    command=command_generate
)
button_quit = ttk.Button(
    frame_control_general,
    text='Quit',
    command=command_quit
)

entry_generate_count.grid(column=1, row=1, sticky=W)

# Add buttoms to frame
button_update.grid(column=0, row=0, sticky=W)
button_generate.grid(column=0, row=1, sticky=W)
button_quit.grid(column=0, row=2, sticky=W)

var_timeout = StringVar()

var_expiration_height = StringVar()

label_block = ttk.Label(frame_control_general, textvariable=var_block)
label_timeout = ttk.Label(frame_control_general, textvariable=var_timeout)
label_expiration_height = ttk.Label(
    frame_control_general,
    textvariable=var_expiration_height
)

label_timeout.grid(column=0, row=10, sticky=W, columnspan=2)
label_block.grid(column=0, row=11, sticky=W, columnspan=2)
label_expiration_height.grid(column=0, row=12, sticky=W, columnspan=2)


# Define function for Peer tree
def tree_selection_peers(*args) -> None:
    """Event handler for the Peer tree.
    :type args: Event object will be given automatically
    """
    focus = peer_tree.focus()

    if focus in s.peers:
        sel = s.peers[focus]
    else:
        return

    var_ip.set(str(sel.address))
    var_port.set(str(sel.port))
    var_pubkey.set(sel.pubkey.hex())
    var_peer_service.set(sel.service.hex())
    var_cont_tx.set(trans_to_string(sel.cont_tx))


# Define function for User tree
def tree_selection_users(*args) -> None:
    """"Event handler for the User Request Tree.
    :type args: Event object will be given automatically
    """
    focus = user_tree.focus()

    try:
        index = int(user_tree.item(focus)['text'])
    except ValueError:
        return

    if index >= len(s.pending_requests):
        return

    req = s.pending_requests[index]

    var_user_netsize.set(req.network_size)
    var_user_usersize.set(req.user_size)
    var_user_service.set(req.service.hex())
    var_user_capabilities.set(req.capabilities.hex())
    var_user_nonce.set(req.nonce.hex())


# Define function for Network tree
def tree_selection_network(*args) -> None:
    """Event handler for the Network Tree.
    :type args: Event object will be given automatically
    """
    peer_entries = peer_tree.get_children('')
    focus = network_tree.focus()
    t = network_tree.item(focus)['text']

    if t in peer_entries:
        peer_tree.focus(t)
        peer_tree.selection_set(t)
        tree_selection_peers()


if __name__ == '__main__':

    random.seed('test')

    proto1 = bytes([0b00000001])
    proto2 = bytes([0b00000010])
    proto3 = bytes([0b00000100])

    service = bytes([proto1[0] | proto2[0]])

    s = protocol.State(10, 1, 2)

    # Read addresses with funds from file
    my_path = '/'.join(
        os.path.realpath(__file__).split('/')[0:-1])  # Path to this script
    working_dir = my_path + '/../state'  # Path to binary files
    with open(working_dir + '/peers.pyc', 'rb') as file:
        peers = pickle.load(file)

    cur_peer = 0
    while peers[cur_peer].advertized:
        cur_peer += 1

    # Bind event handlers to corresponding trees
    peer_tree.bind('<<TreeviewSelect>>', tree_selection_peers)
    user_tree.bind('<<TreeviewSelect>>', tree_selection_users)
    network_tree.bind('<<TreeviewSelect>>', tree_selection_network)

    # Give same importance to all rows and columns
    root.columnconfigure(0, weight=1)
    root.columnconfigure(1, weight=1)
    root.columnconfigure(2, weight=1)
    root.rowconfigure(0, weight=0)
    root.rowconfigure(1, weight=1)

    print('In case you get an error that there are no funds available you cannot'
          'see any peers, execute \'anonboot/generate-initial-funds.py\'!')

    # Update information displayed on startup
    command_update()
    # Show the graphical interface
    root.mainloop()
