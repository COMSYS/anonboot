#!/usr/bin/python3
"""
Contains the implementation of the actual protocol.
"""
from collections import namedtuple, OrderedDict
from typing import Union, Type, List, Dict
import hashlib
import sys

import ipaddress
from bitcoinrpc.authproxy import AuthServiceProxy
import opreturn
import pow
import ecdsa
from Cryptodome.Random.random import StrongRandom, getrandbits
from Crypto.Random.Fortuna.FortunaGenerator import \
    AESGenerator as SeedablePrngGenerator

from config import EVAL, BASIC_MODE, DEACTIVATE_EXPIRATION_HEIGHT

# Basic Mode via console-------------------------------------------------------
if len(sys.argv) > 1 and sys.argv[1] == '-i':
    # Network construction is independent of users in Basic mode
    BASIC_MODE = True

# Constants--------------------------------------------------------------------
PROTOCOL_PREFIX = b'AB'
PROTOCOL_VERSION = b'\x01'
LENGTH_VAR = "var"
MessageField = namedtuple('MessageField', 'name length')

# -Validity-Period-Definitions-------------------------------------------------
L_S = 1  # Modulo at which a PEER ANNOUNCEMENT/ USER REQUEST can be published.
# E.g. if L_S = 10, announcements can only be made in blocks with (b%10) == 0:
# 10,20,30 etc.
FUZZY = 0  # Number of blocks an peer announcement may be delayed. I.e. how
# many blocks later then the original announcement block is an announcement
# possible?
K = 1  # Intervals that a announcement/ request is valid
# -----------------------------------------------------------------------------


class AnonbootValueError(ValueError):
    pass


class AnonbootWrongVersionError(AnonbootValueError):
    pass


class AnonbootWrongPrefixError(AnonbootValueError):
    pass


class BaseMessage:
    """Abstract class message types can inherit from

    Attributes
    -----------
    The base class itself has no attributes, but inherited classes MUST define
    the attribute "LAYOUT"

    Methods
    -------
    _parse(message: bytes)
        Parses message according to LAYOUT and adds the contents as attributes.
        Intended for internal use only (gets called by __init__)
    """

    LAYOUT = OrderedDict()  # to overwrite

    def __init__(self, message: bytes):
        """
        Parameters
        ----------
        message : bytes
            The byte message to parse, which initializes the instance
            attributes
        """
        self.MIN_LENGTH = sum([
            0 if length == "var" else length
            for _, length in self.LAYOUT.items()
        ])

        if len(message) < self.MIN_LENGTH:
            print('Erroneous message length: {} / {}'.format(len(message), self.MIN_LENGTH))
            print('Message: {}'.format(message))
            raise ValueError("Invalid message length")

        self._parse(message)

    def _parse(self, message: bytes) -> None:
        """Parses message according to LAYOUT and adds the contents as
        attributes.
        Note that all attributes are then bytes() objects
        Intended for internal use only (gets called by __init__)"""

        index = 0

        for l_name, l_length in self.LAYOUT.items():
            if l_length == LENGTH_VAR:
                length = message[index]
                index += 1
            else:
                length = l_length

            setattr(self, l_name, message[index:index + length])
            index += length

        if index != len(message):
            raise ValueError("Did not correctly parse the whole message")


class PeerAdvertisement(BaseMessage):
    """Defines the Layout of peer advertisements

    Attributes
    -----------
    TYPE_PREFIX : bytes
        The message prefix for peer ads, to differentiate them from e.g.
        user requests
    LAYOUT : OrderedDict
        Defines the peer ad layout. Has entries of form "name" : length,
        where length is the length of the field in bytes. Order of entries
        is the order of fields in message. Note that a PROTOCOL_PREFIX and
        the TYPE_PREFIX get added separately in Peer.advertise()

    Other Attributes: Same as PeerInfo below

    Example: If m is a bytes object representing a peer advertisement as found
             on the blockchain, then you can do:
             ad = PeerAdvertisement(m)
             print(ad.port)
             Note that all attributes are bytes objects."""

    TYPE_PREFIX = 0b0001
    LAYOUT = OrderedDict([
        ('flags', 1),
        ('pubkey', 33),
        ('ip', 16),
        ('port', 2),
        ('service', 2),
        ('capabilities', 14),
        ('powork', pow.NONCE_LENGTH)
    ])

    def __init__(self, message: bytes):
        self.flags: bytes = bytes()
        self.direct_key: bool = False
        self.is_ipv6: bool = False
        self.ip: bytes = bytes()
        self.port: bytes = bytes()
        self.pubkey: bytes = bytes()
        self.service: bytes = bytes()
        self.capabilities: bytes = bytes()
        self.powork: bytes = bytes()
        super().__init__(message)


class UserRequest(BaseMessage):
    """Defines the Layout of user requests, analogous to PeerAdvertisement

    Attributes
    -----------
    TYPE_PREFIX : bytes
        The message prefix for peer ads, to differentiate them from e.g.
        user requests
    LAYOUT : OrderedDict
        Defines the peer ad layout. Has entries of form "name" : length,
        where length is the length of the field in bytes. Order of entries
        is the order of fields in message. Note that a PROTOCOL_PREFIX and
        the TYPE_PREFIX get added separately in Peer.advertise()

    Other Attributes: Same as UserInfo below
    """

    TYPE_PREFIX = 0b0010
    LAYOUT = OrderedDict([
        ('service', 2),
        ('network_size', 1),
        ('user_size', 1),
        ('capabilities', 12),
        ('nonce', 8)
    ])

    def __init__(self, message: bytes):
        self.service: bytes = bytes()
        self.network_size: bytes = bytes()
        self.user_size: bytes = bytes()
        self.capabilities: bytes = bytes()
        self.nonce: bytes = bytes()
        super().__init__(message)


BlockData = namedtuple('BlockData', 'ads requests merkle')
BlockData.__doc__ = """Tuple including peer ads and user requests of one
specific block

Attributes
----------
ads : PeerInfo
    The peer advertisements of the block
requests : UserInfo
    The user requests of the block
merkleroot : str
    merkleroothash of the block"""

PeerInfo = namedtuple('PeerInfo', 'direct_pubkey is_ipv6 address port pubkey service capabilities block cont_tx')
PeerInfo.__doc__ = """Representation of processed PeerAdvertisement, 
i.e. represents a peer

Attributes
----------
direct_pubkey : bool
    True if peer set D-flag in advertisement
is_ipv6 : bool
    True, if peer advertised IPv6 address
address : ipaddress.ip_address
    IP of the peer
port : int
    Port of peer
pubkey : bytes
    Public (elliptic curve) key of peer
service : bytes
    ID of the service offered by peer
capabilities : bytes
    Service-specific capabilities advertised by the peer
block : int
    Block in which this peer was advertised (used for expiration)
cont_tx : protocol.Transaction
    Change address used for validating identity of peer in updates
"""

UserInfo = namedtuple(
    'UserInfo',
    'service network_size user_size capabilities nonce block txid')
UserInfo.__doc__ = """Representation of processed UserRequest, 
i.e. represents a request

Attributes
----------
service : bytes
    The higher layer service the user requests
network_size : int
    Minimum amount of peers in network the user requests
user_size : int
    Minimum amount of users (including sender) user requests
capabilities : bytes
    Custom capabilities requested (specific to the requested service)
nonce : bytes
    Nonce used for seeding RNG for peer selection
block : int
    Block in which the request was included (used for expiration)
txid
    TXID of transaction request was included in (used for identification)
"""


def _get_last_merkle_root_before(
        blockheight: int,
        l_s: int,
        fuzzy: int
    ) -> str:
    """
    Return the merkle root of the last pulse block before the specified height
    (necessary for PoW Seed computation). Before, even if the current block is
    a pulse block itself!

    :param blockheight: The current blockheight
    :param l_s: pulse duration
    :param fuzzy: length of negotiation phase
    :return: merkle root of the previous pulse block
    """
    # Connect to RPC
    con = AuthServiceProxy(
        "http://%s:%s@127.0.0.1:%s" % (
            State.RPC_USER, State.RPC_PASSWORD, State.PORT))

    if blockheight % l_s != 0 and blockheight % l_s <= fuzzy:
        # In case the ad is in a fuzzy block, we have to go back one more
        # interval
        blockheight -= blockheight % l_s

    height = l_s * ((blockheight - 1) // l_s)
    hash_val = con.getblockhash(height)
    block = con.getblock(hash_val)
    merkle = block["merkleroot"]
    return merkle


def _supports_alg(user_alg: bytes, peer_alg: bytes) -> bool:
    """
    Return whether the peer supports the algorithm specified by the user.

    :param user_alg: Service ID requested by user
    :param peer_alg: Service ID offered by privacy peer
    :return: True, if algorithm  is supported by the peer
    """
    return (user_alg == peer_alg)


def _bytes_to_int(data: bytes) -> int:
    """Convert a big endian byte array to an integer."""
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(number: int) -> bytes:
    """Convert integer to byte array in big endian format"""
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')


def _add_wrapper(msg: bytearray, msg_type: Type[BaseMessage]) -> None:
    """Add wrapper to the given message with correct type prefix."""
    # NOTE: Since we always prepend, the actual order is proto_pref, type_pref
    # This is stupidly hacked, but I didn't want to change it now
    type_and_flags = msg_type.TYPE_PREFIX << 4 & 0xF0
    # print('Msg before: {}'.format(msg))
    msg.insert(0, type_and_flags)
    msg.insert(0, ord(PROTOCOL_VERSION))
    msg.insert(0, PROTOCOL_PREFIX[1])
    msg.insert(0, PROTOCOL_PREFIX[0])
    # print('Msg after: {}'.format(msg))


def _var_length_field(field: bytes) -> bytes:
    """Returns the message representation of a variable length field
       (currently just length + field)"""
    if len(field) > 255:
        # Length has to be representable by one byte
        raise ValueError("Var fields cannot exceed 255 bytes")
    return bytes([len(field)]) + field


def _bytes_from_hexstring(hexstr: str) -> bytes:
    """Convert a hex string to a bytes array"""
    return bytes(bytearray.fromhex(hexstr))


def _compute_network_seed(
        service: bytes,
        peer_size: int,
        user_size: int,
        merkle: str
    ) -> bytes:
    """Compute the seed that is used for the peer selection of a NW. It
    consists of the service supported by the network, the number of peers
    and users respectively and the merkleroothash of the block in which the
    network is created.
    """
    return service + int_to_bytes(peer_size) + int_to_bytes(
        user_size) + bytes(merkle, 'utf-8')


def is_valid_utxo(utxo: opreturn.Transaction) -> bool:
    """Return true, if the given transaction is spendable."""
    txid = utxo.txid
    vout = utxo.vout
    connection = AuthServiceProxy(
        "http://%s:%s@127.0.0.1:%s" % (
            State.RPC_USER, State.RPC_PASSWORD, State.PORT))

    spendable = connection.listunspent()
    for tx in spendable:
        if tx["txid"] == txid and tx["vout"] == vout:
            return True


def _process_user_request(message: opreturn.OpData, simulated: bool = False) -> UserInfo:
    """Construct a user request object from the given message."""
    request = UserRequest(bytes.fromhex(message.hex[8:]))

    net_size = _bytes_to_int(request.network_size)
    user_size = _bytes_to_int(request.user_size)

    if simulated:
        block = 0
        txid = bytes([0x00] * 32)
    else:
        block = message.block
        txid = message.tx_out.txid

    return UserInfo(
        request.service,
        net_size,
        user_size,
        request.capabilities,
        request.nonce,
        block,
        txid
    )


def _calc_peer_validity(block_height: int, win_size: int) -> int:
    """
    Calculate lower bound for blocks with valid advertisements and requests.
    :param block_height: Current Block height
    :param win_size: Window Size
    :return: The lowest block that contains still valid ads/requests
    """
    return (block_height // win_size) * win_size


def _sample(seed: bytes, population: list, k: int) -> list:
    """
    Randomly select k elements from the population with randomness based
    on the given seed
    :param seed: Seed for the random function
    :param population: The population to draw from
    :param k: Number of elements to select
    :return: List with the selected elements
    """
    prng = SeedablePrngGenerator()
    prng.reseed(seed)
    sr = StrongRandom(randfunc=prng.pseudo_random_data)
    return sr.sample(population, k)


# Start of Classes-------------------------------------------------------------
class State:
    """Class that does the protocol logic: parse blockchain, parse messages,
       add peers and create networks

    Attributes
    -----------
    peers : Dict[str, PeerInfo]
        Dictionary keeping track of the ALREADY VALIDATED peers.
        Keys: String of hex representation of public key of peer
        Value: PeerInfo representing the peer
    times_seen : Dict[str, int]
        Counts the number of Ads per public key
    consecutive_seen : Dict[str, int]
        Counts the number of consecutive Ads per public key
    pending_requests : List[UserInfo]
        List keeping track of not yet expired user requests, that did not get
        served yet
    networks : List[Network]
        List keeping track of created networks
    current_block : int
        Integer representing the last already processed block by update() (i.e.
        the current block state). The blockchain may already have moved on,
        current_block gets changed in update()
    request_watch : set
        Set of watched user requests
    served_requests : Dict
        Dict with all server user requests
    peer_buffer : List
        List of peers to advertise in next pulse block
    user_buffer : List
        List of user requests to be published in next pulse block
    used_utxos : List
        Eval only
    l_s : int
        Length of one pulse
    fuzzy : int
        Length of negotiation phase
    l_v : int
        Possible extended pulse length
    expiration_height : int
        Largest interval to find valid information
    Methods
    -------
    update()
        Parses unprocessed blocks from blockchain, searches for messages of our
        protocol and processes them. Updates the state (pending requests, peers
        and networks) accordingly
    watch_request(txid: str)
        Tells state to keep track of the request when served (in
        served_requests)
    generate(amount: int)
        Generate the given number of blocks and add buffered user requests
        and peer advertisements to the blockchain if a suitable pulse block is
        mined
    advertise_peer(peer: Peer, peer_ad_hex: str)
        Add a peer Ad to the buffer
    request_user(user: User, request_hex: str)
        Add a user request to the buffer
    count_peers_with_alg(alg: bytes)
        Count the number of peers supporting the given algo in current state
    get_networks_of_peer(pubkey: Union[str, bytes]) -> list:
        Return a list of all networks the peer belongs to
    exists_peer(pubkey :str) -> bool
        Checks if a peer with the given public key exists
    pop_served_request(self, txid: str) -> dict:
        Return the served request with the given transaction ID
    """

    RPC_USER = "Bob"
    RPC_PASSWORD = "test"
    PORT = 18443

    def __init__(self, l_s: int = L_S, k: int = K, fuzzy: int = FUZZY):
        """
        Initialize State parameters.
        :param l_s: Pulse length
        :param k:  Multiplicator for extended pulse length
        :param fuzzy: Length of negotiation phase
        """
        if EVAL:
            self.source_tx = None
        self.peers = {}
        self.times_seen = {}
        self.consecutive_seen = {}
        self._new_consecutive_seen = {}
        self.pending_requests = []
        self.networks = []

        self.current_block = 0

        # Requests whose txid is in request_watch get entry in served_requests
        # with associated network when served. Other requests simply get
        # deleted when served.
        self.request_watch = set()
        self.served_requests = {}

        # Buffers for Advertisements that have to wait for the next suitable
        # blog
        self.peer_buffer = []
        self.user_buffer = []

        self.used_utxos = []

        self.l_s = l_s
        self.fuzzy = fuzzy
        self.l_v = k * l_s
        self.expiration_height = self.l_v + l_s
        if DEACTIVATE_EXPIRATION_HEIGHT:
            self.expiration_height = 1000000

    def generate(self, amount: int) -> None:
        """
        Generate the given number of blocks and add buffered user requests
        and peer advertisements to the blockchain if a suitable block is
        mined

        :amount: int : Number of blocks to generate
        """
        con = AuthServiceProxy(
            "http://%s:%s@127.0.0.1:%s" % (
                self.RPC_USER, self.RPC_PASSWORD, State.PORT))

        # Compute # blocks before next announcement block

        #  Get current block height
        current_height = con.getblockcount()

        if (current_height % self.l_s) - self.fuzzy < 0:
            # We are already in a suitable block
            pre = 0
        else:
            pre = self.l_s * ((current_height // self.l_s) + 1) - (
                    current_height + 1)
            # Genrate prev blocks
            if amount > pre:
                con.generate(pre)
            else:
                con.generate(amount)
                return

        # This list is necessary because we may need to reuse an address
        # straight away.
        change_addresses = []
        reused = 0
        while len(self.peer_buffer) != 0:
            (peer, peer_ad_hex) = self.peer_buffer.pop()
            if peer.cont_tx in self.used_utxos:
                del self.used_utxos[peer.cont_tx]

            # EVAL: Avoid coinbase transaction
            if EVAL:
                peer.cont_tx = self.source_tx.pop(0)
                while (not is_valid_utxo(peer.cont_tx)) and (
                        peer.cont_tx not in change_addresses):
                    peer.cont_tx = self.source_tx.pop(0)
                if peer.cont_tx in change_addresses:
                    if reused == 0:
                        print("\nWarning: Change address reuse")
                    reused += 1
                    change_addresses.remove(peer.cont_tx)
            # Write peer advertisement into blockchain
            new_cont_tx = opreturn.send_data(
                con, peer_ad_hex, tx_ins=[peer.cont_tx])
            peer.cont_tx = new_cont_tx

            if EVAL:
                # Change address can be used again
                self.source_tx.append(new_cont_tx)
                change_addresses.append(new_cont_tx)

        if reused > 0:
            print("Warning: Reuse of change address {} times.".format(reused))
        reused = 0

        while len(self.user_buffer) != 0:
            (user, request_hex) = self.user_buffer.pop()
            if not EVAL:
                # Write user requests into blockchain
                request_tx = opreturn.send_data(con, request_hex)
            else:
                # Get one fund address
                # EVAL: Avoid coinbase transaction
                cont_tx = self.source_tx.pop(0)
                while not is_valid_utxo(
                        cont_tx) and cont_tx not in change_addresses:
                    cont_tx = self.source_tx.pop(0)
                if cont_tx in change_addresses:
                    if reused == 0:
                        print("\nWarning: Change address reuse")
                    reused += 1
                    change_addresses.remove(cont_tx)

                request_tx = opreturn.send_data(con, request_hex,
                                                tx_ins=[cont_tx])
                # Change address can be used again
                self.source_tx.append(request_tx)
                change_addresses.append(request_tx)
            user._request_txid = request_tx.txid

        if reused > 0:
            print("Warning: Reuse of change address {} times.".format(reused))

        con.generate(amount - pre)

    def advertise_peer(self, peer, peer_ad_hex: str) -> None:
        """Add a peer advertisement to the list of buffered advertisements

        :peer: Peer :
            The peer to advertise
        :peer_ad_hex: str :
            The advertisement as hex
        """
        self.peer_buffer.append((peer, peer_ad_hex))

    def request_user(self, user, request_hex: str) -> None:
        """Add a user request to the state buffer

        :user: User :
            The User that requests
        :request_hex: str :
            The request in hex
        """
        self.user_buffer.append((user, request_hex))

    def count_peers_with_alg(self, alg: bytes) -> int:
        """Return number of peers that support the given algorithm."""
        return len(
            [p for p, v in self.peers.items() if _supports_alg(alg, v.service)])

    def get_networks_of_peer(self, pubkey: Union[str, bytes]) -> list:
        """Return the networks the peer with the give pubKey belongs to.

        :pubkey: Union[str, bytes] :
            Public key of the peer to look for
        :return:
            List of all networks the peer is a part of
        """
        if isinstance(pubkey, str):
            byte_pubkey = _bytes_from_hexstring(pubkey)
        elif isinstance(pubkey, bytes):
            byte_pubkey = pubkey
        else:
            raise TypeError("PubKey has to be either string or bytes array!")

        return [n for n in self.networks if byte_pubkey in n.peers]

    def watch_request(self, txid: str) -> None:
        """Instructs the state to remember the network associated with 
        this request if it gets served

        :txid:
            ID of the transaction to watch
        """
        self.request_watch.add(txid)

    def _update_block(
            self, block_height: int,
            block_data: opreturn.OpData
    ) -> None:
        """Update the state by using the data found in the current block.

        :block_height: int :
            Heioght of the block to update
        :block_data: opreturn.OpData:
            Data of the block to update
        """
        self._expire_peers_and_user_requests(block_height)

        self._expire_networks(block_height)

        # Add advertisements found in the block
        for a in block_data.ads:
            # Add new peers to state
            pubkey = a.pubkey.hex()
            self.peers[pubkey] = a
            if pubkey in self.consecutive_seen:
                self._new_consecutive_seen[pubkey] = self.consecutive_seen[pubkey] + 1
                self.consecutive_seen[pubkey] += 1
            else:
                self._new_consecutive_seen[pubkey] = 1
                self.consecutive_seen[pubkey] = 1
            if pubkey in self.times_seen:
                self.times_seen[pubkey] += 1
            else:
                self.times_seen[pubkey] = 1
        # Only update if the last fuzzy block has been passed
        if block_height == _calc_peer_validity(block_height, self.l_v) + self.fuzzy:
            self.consecutive_seen = self._new_consecutive_seen
            self._new_consecutive_seen = {}
        # Add user requests found in the block
        for r in block_data.requests:
            # Add the new requests to pending request state
            self.pending_requests.append(r)

        # ------------------- Try to construct new NWs ------------------------
        # Check for all pending requests whether they can be used for a NW
        # We sort by descending NW size so that larger NWs have a higher prob.
        # to be created

        changed = True
        # If someone joins a NW it may now be large enough for another user
        if block_height == _calc_peer_validity(block_height, self.l_v) + self.fuzzy:
            # We only want to construct networks after the last fuzzy block
            while changed:
                changed = False
                sorted_requests = sorted(self.pending_requests, key=lambda x: x.network_size, reverse=True)
                for r in sorted_requests:
                    # Add new networks (and delete from pending requests)

                    # Check if there are enough peers
                    net_size = r.network_size
                    if self.count_peers_with_alg(r.service) < net_size:
                        if not BASIC_MODE:
                            # There may still be an existing suitable NW
                            changed = changed or self._try_joining_nw(r)
                        continue

                    # Count user requests with equal service and capabilities
                    # and <= size
                    matches = [
                        req for req in self.pending_requests
                            if req.service == r.service
                                and req.capabilities == r.capabilities
                                and req.network_size <= net_size
                                and req.user_size <= r.user_size
                    ]
                    if len(matches) >= r.user_size or (
                            BASIC_MODE and len(matches) > 0):
                        # We have enough matching requests for a network (in
                        # basic mode, networks are always created,
                        # even if there are not enough
                        if BASIC_MODE:
                            user_independent_seed = _compute_network_seed(
                                r.service,
                                net_size,
                                r.user_size,
                                block_data.merkle
                            )
                        else:
                            user_independent_seed = _compute_network_seed(
                                r.service,
                                net_size,
                                len(matches),
                                block_data.merkle
                            )
                        new_net_peers = self._peer_selection(
                            matches,
                            net_size,
                            user_independent_seed
                        )
                        if BASIC_MODE:
                            new_net = Network(
                                service=r.service,
                                capabilities=r.capabilities,
                                peers=new_net_peers,
                                creation=block_height,
                                user_size=r.user_size
                            )
                        else:
                            new_net = Network(
                                service=r.service,
                                capabilities=r.capabilities,
                                peers=new_net_peers,
                                users=matches,
                                creation=block_height
                            )
                        self.networks.append(new_net)

                        self._handle_served_requests(matches, new_net)
                        changed = True
                    elif not BASIC_MODE:
                        # There may still be an existing suitable NW
                        # But joining only makes sense in non basic mode
                        changed = changed or self._try_joining_nw(r)

    def _try_joining_nw(self, r: UserInfo) -> bool:
        """Try to join a suitable NW. Return True on success

        :r: UserInfo :
            The user that might be joined to an existing NW
        :return: bool:
            True on success, False else
        """
        # Count requests with equal service and capabilities and <= size
        matches = [
            req for req in self.pending_requests
                if req.service == r.service
                    and req.capabilities == r.capabilities
                    and req.network_size <= r.network_size
                    and req.user_size <= r.user_size
        ]
        candidate_nws = [n for n in self.networks if
                         n.get_net_size() >= r.network_size
                         and n.get_user_size() + len(matches) >= r.user_size]
        # + matches because the users would be added themselves
        if len(candidate_nws) == 0:
            # No suitable NWs found
            return False
        seed = ""
        for nw in candidate_nws:
            seed += str(b"".join([r.nonce for r in nw.users]))
        seed += str(b"".join([r.nonce for r in matches]))
        chosen_nw = _sample(bytes(seed, 'utf-8'), candidate_nws, 1)[0]
        for u in matches:
            chosen_nw.add_user(u)
        self._handle_served_requests(matches, chosen_nw)
        return True

    def _handle_served_requests(
            self,
            matches: List[UserInfo],
            network
    ) -> None:
        """Remove the requests from pending list and and add watched requests 
        to  served request dict.

        :matches: List[UserInfo]:
            List of all users that were joined to a network
        :network: Network:
            The network the users were added to
        """
        for req in matches:
            # If we watch the served request, we add it to served request dict
            if req.txid in self.request_watch:
                self.served_requests[req.txid] = network

        # Delete ALL served requests from pending list
        self.pending_requests[:] = [
            p_r for p_r in self.pending_requests if p_r not in matches
        ]

    def pop_served_request(self, txid: str) -> dict:
        """Return the served request belonging to the given transaction ID"""
        if txid not in self.served_requests:
            raise ValueError("Request not served")
        else:
            return self.served_requests[txid]

    def _expire_peers_and_user_requests(
            self,
            block_height: int = 0,
            expire_all: bool = False
    ) -> None:
        """Delete expired peers and user requests

        :block_height: int:
            Current block height
        :expire_all: bool:
            If set, assume all peer advertisements and
            service requests should be expired (eval).
        """
        if expire_all:
            for k in self.peers.keys():
                del self.peers[k]
            return

        # Everything strictly smaller than this expires
        validity_period = _calc_peer_validity(
            block_height,
            self.l_v
        )

        #  Delete expired peers (and networks with them)
        for k, v in list(self.peers.items()):
            if v.block < validity_period:
                # Delete peer
                del self.peers[k]

        # Delete expired requests
        self.pending_requests[:] = [
            r for r in self.pending_requests if r.block >= validity_period
        ]

    def _expire_networks(
            self,
            block_height: int = 0,
            expire_all: bool = False
    ) -> None:
        """Remove expired networks from state

        :block_height: int:
            Current block height
        :expire_all: bool:
            If set, assume all networks should be
            expired (eval).
        """
        if expire_all:
            self.networks = list()
            return

        validity_period = _calc_peer_validity(block_height, self.l_v) + self.fuzzy
        new = []
        for n in self.networks:
            if n.creation < validity_period:
                # Something with below line does not work, that's why
                # we use the else.
                # self.networks.remove(n)
                pass
            else:
                new.append(n)
        self.networks = new

    def update(self, until: int = None) -> None:
        """Update the state with the information from all blocks added 
        since the last checked block.

        :until: int:
            Used for Eval. Only update until specified block.
        """

        # Connect to RPC
        connection = AuthServiceProxy(
            "http://%s:%s@127.0.0.1:%s" % (
                State.RPC_USER, State.RPC_PASSWORD, State.PORT))

        #  Get current block height
        current_height = connection.getblockcount()
        if until is not None:
            current_height = until

        # We need to at most update the state from the expiration height
        self.current_block = max(
            self.current_block,
            current_height - self.expiration_height)
        if self.current_block > current_height:
            raise RuntimeError(
                "State block height higher than actual block height")
        if self.current_block == current_height:
            # Nothing to do
            return

        # Get all new Peer Ads and User Requests
        data = opreturn.get_data_from_block_range(
            connection, self.current_block + 1, current_height, self.l_s,
            self.fuzzy)

        # Parse the Peer Ads and User Requests and possibly add them
        pending_data = {}
        for m in data:
            try:
                message = self._parse_message(m)
            except AnonbootWrongPrefixError:
                # Just skip irrelevant messages
                pass
            else:
                # Create the lists if they don't already exist
                if m.block not in pending_data:
                    pending_data[m.block] = BlockData([], [], m.merkle)

                if isinstance(message, PeerInfo):
                    pending_data[m.block].ads.append(message)
                elif isinstance(message, UserInfo):
                    pending_data[m.block].requests.append(message)
                else:
                    raise ValueError("Unknown data in block")

        # Update for each block missed
        for height in range(self.current_block + 1, current_height + 1):
            if height in pending_data:
                block_data = pending_data[height]
            else:
                block_data = BlockData([], [], "")
            self._update_block(height, block_data)

        # Update state block_height
        self.current_block = current_height


    def update_simulated(self, ads: list=list(), reqs: list=list()) -> None:
        """Update the state with the information from manually
        crafted peer advertisements and service requests.

        Copied from _update_block

        :ads: list:
            List of peer advertisements (PeerInfo) considered.
        :reqs: list:
            List of service requests (UserInfo) considered.
        """

        # We use a random merkleroothash
        dummy_merkle = hashlib.sha256(getrandbits(256).to_bytes(32, 'big')).digest().hex()
        dummy_block_data = BlockData(ads, reqs, dummy_merkle)
        dummy_block_height = 0

        self._expire_peers_and_user_requests(expire_all=True)
        self._expire_networks(expire_all=True)

        # Add advertisements found in the block
        for a in ads:
            # Add new peers to state
            a = self._process_peer_advertisement(a, simulated=True)
            pubkey = a.pubkey.hex()
            self.peers[pubkey] = a
            if pubkey in self.consecutive_seen:
                self._new_consecutive_seen[pubkey] = self.consecutive_seen[pubkey] + 1
                self.consecutive_seen[pubkey] += 1
            else:
                self._new_consecutive_seen[pubkey] = 1
                self.consecutive_seen[pubkey] = 1
            if pubkey in self.times_seen:
                self.times_seen[pubkey] += 1
            else:
                self.times_seen[pubkey] = 1
        # Contrary to real statistics, in eval we always update
        self.consecutive_seen = self._new_consecutive_seen
        self._new_consecutive_seen = {}
        # Add user requests found in the block
        for r in reqs:
            # Add the new requests to pending request state
            r = _process_user_request(r, simulated=True)
            self.pending_requests.append(r)

        # ------------------- Try to construct new NWs ------------------------
        # Check for all pending requests whether they can be used for a NW
        # We sort by descending NW size so that larger NWs have a higher prob.
        # to be created

        changed = True
        # If someone joins a NW it may now be large enough for another user
        # Contrary to real bootstrapping, we always assume now is the spawn block in eval
        while changed:
            changed = False
            sorted_requests = sorted(self.pending_requests, key=lambda x: x.network_size, reverse=True)
            for r in sorted_requests:
                # Add new networks (and delete from pending requests)

                # Check if there are enough peers
                net_size = r.network_size
                if self.count_peers_with_alg(r.service) < net_size:
                    if not BASIC_MODE:
                        # There may still be an existing suitable NW
                        changed = changed or self._try_joining_nw(r)
                    continue

                # Count user requests with equal service and capabilities
                # and <= size
                matches = [
                    req for req in self.pending_requests
                        if req.service == r.service
                            and req.capabilities == r.capabilities
                            and req.network_size <= net_size
                            and req.user_size <= r.user_size
                ]
                if len(matches) >= r.user_size or (BASIC_MODE and len(matches) > 0):
                    # We have enough matching requests for a network (in
                    # basic mode, networks are always created,
                    # even if there are not enough
                    if BASIC_MODE:
                        user_independent_seed = _compute_network_seed(
                            r.service,
                            net_size,
                            r.user_size,
                            dummy_block_data.merkle
                        )
                    else:
                        user_independent_seed = _compute_network_seed(
                            r.service,
                            net_size,
                            len(matches),
                            dummy_block_data.merkle
                        )
                    new_net_peers = self._peer_selection(
                        matches,
                        net_size,
                        user_independent_seed
                    )
                    if BASIC_MODE:
                        new_net = Network(
                            service=r.service,
                            capabilities=r.capabilities,
                            peers=new_net_peers,
                            creation=dummy_block_height,
                            user_size=r.user_size
                        )
                    else:
                        new_net = Network(
                            service=r.service,
                            capabilities=r.capabilities,
                            peers=new_net_peers,
                            users=matches,
                            creation=dummy_block_height
                        )
                    self.networks.append(new_net)

                    self._handle_served_requests(matches, new_net)
                    changed = True
                elif not BASIC_MODE:
                    # There may still be an existing suitable NW
                    # But joining only makes sense in non basic mode
                    changed = changed or self._try_joining_nw(r)

        # Update state block_height
        # Write dummy value since we get out of sync with Bitcoin blockchain here
        self.current_block = 0


    def _peer_selection(self, user_requests: list, net_size: int,
                        user_independent_seed: bytes) -> tuple:
        """Select peers for the given user requests requesting the net_size
        to form a new NW.

        :user_requests: list[UserInfo] :
            The User Requests for the new network
        :net_size: int :
            Size of the network to create
        :user_independent_seed: bytes :
            The part of the seed that is indepent of the user seeds
        :return: Tuple[PeerInfo]:
            Tuple of the selected peers
        """
        if not user_requests:
            raise ValueError("User Request list must not be empty.")

        # All users request same service,
        # otherwise they would not have been matched
        user_alg = user_requests[0].service
        peer_list = [
            v.pubkey for _, v in self.peers.items()
            if _supports_alg(user_alg, v.service)
        ]
        peer_list.sort()

        # Add user NONCEs to seed
        seed = b"".join([r.nonce for r in user_requests])
        seed += user_independent_seed
        return tuple(_sample(seed, peer_list, net_size))

    def _validate_cont_tx(self, pubkey: Union[bytearray, bytes],
                          tx_in: opreturn.Transaction) -> bool:
        """Check if tx_in is the cont_tx of the user identified by the
        given public key"""
        pubhex = pubkey.hex()
        if pubhex in self.peers:
            if self.peers[pubhex].cont_tx == tx_in:
                return True
        else:
            # This is the origin tx for this peer
            return True

        return False

    def _process_peer_advertisement(self, message: opreturn.OpData, simulated: bool = False) -> PeerInfo:
        """Validate if a peer ad is valid and construct an object, if it is.

        :message: opreturn.OpData:
            Message to process
        :simulated: bool:
            If true, bypass proper PoW check (eval)
        :return: PeerInfo :
            The resulting PeerInfo Object
        """
        peer_ad = PeerAdvertisement(bytes.fromhex(message.hex[8:]))
        if not simulated:
            valid_ad = pow.validate_powork(
                    peer_ad.powork,
                    peer_ad.pubkey,
                    _get_last_merkle_root_before(
                        message.block,
                        self.l_s,
                        self.fuzzy
                        )
                    ) and self._validate_cont_tx(peer_ad.pubkey, message.tx_in)
        else:
            valid_ad = True
        if (valid_ad):
            try:
                flags = peer_ad.flags
                is_ipv6 = ord(flags) >> 7
                if is_ipv6:
                    ip = ipaddress.IPv6Address(peer_ad.ip)
                else:
                    ip = ipaddress.IPv4Address(peer_ad.ip[:4])
                port = _bytes_to_int(peer_ad.port)
                pubkey = bytes(peer_ad.pubkey)
                service = bytes(peer_ad.service)
                capabilities = bytes(peer_ad.capabilities)
            except ValueError:
                raise ValueError("Invalid peer advertisement")
            else:
                return PeerInfo(
                    is_ipv6=is_ipv6,
                    direct_pubkey=False,  # Don't use this now
                    address=ip,
                    port=port,
                    pubkey=pubkey,
                    service=service,
                    capabilities=capabilities,
                    block=message.block,
                    cont_tx=message.tx_out
                )
        else:
            raise ValueError("Invalid peer advertisement")

    def _parse_message(self, message: opreturn.OpData) -> Union[PeerInfo, UserInfo]:
        """Read the message type and process it accordingly.

        :message: opreturn.OpData :
            message to process
        :return: Union[PeerInfo, UserInfo]
            The processed message
        """
        # wrapper = Wrapper(bytes.fromhex(message.hex))
        byte_message = bytes.fromhex(message.hex)

        m_prefix = byte_message[:2]
        m_version = byte_message[2]
        m_type = byte_message[3] >> 4

        if m_prefix != PROTOCOL_PREFIX:
            raise AnonbootWrongPrefixError("Wrong message prefix")
        if m_version != ord(PROTOCOL_VERSION):
            raise AnonbootWrongVersionError("Wrong message version")

        if m_type == PeerAdvertisement.TYPE_PREFIX:
            res = self._process_peer_advertisement(message)
            return res
        elif m_type == UserRequest.TYPE_PREFIX:
            res = _process_user_request(message)
            return res
        else:
            raise AnonbootValueError("Unknown message type")

    def exists_peer(self, pubkey: str) -> bool:
        """Check if a peer with the given public key is connected."""
        return pubkey in self.peers


class Network:
    """
    Class representing one created NW

    Attributes
    ----------
    service : bytes
        Higher layer service
    capabilities : bytes
        Optional higher layer capabilities
    peers : Tuple[PeerInfo]
        The peers of the network
    users: List[UserInfo]
        The users in the network
    creation : int
        block at which the NW was created

     Methods
    -------
    add_user( User) -> None
        Adds an user to the NW
    get_net_size() ->  int
        Returns the # of peers in the NW
    get_user_size() -> int
        Returns the # of users in the NW
    """

    def __init__(self,
            service: bytes,
            capabilities: bytes,
            peers: tuple,
            creation: int,
            users: list = None,
            user_size: int = 0
        ):
        self.service = service
        self.capabilities = capabilities
        self.peers = peers
        if not BASIC_MODE:
            # In basic mode users are not bound to NWs.
            self.users = users
        else:
            self.user_size = user_size
        self.creation = creation

    def get_net_size(self) -> int:
        """Returns the number of peers in this network"""
        return len(self.peers)

    def get_user_size(self) -> int:
        """Returns the number of users in this network"""
        if BASIC_MODE:
            return self.user_size
        else:
            return len(self.users)

    if not BASIC_MODE:
        def add_user(self, user) -> None:
            """Joins a user to this NW"""
            self.users.append(user)


class User:
    """Class representing a user REQUEST AND a User!

    Attributes
    ----------
    service : bytes
        Higher layer service
    network_size : int
        Minimal number of peers in requested network
    user_size : int
        Minimal number of users in requested network
    capabilities: bytes
        Required capabilities for higher layer service
    nonce: bytes
        Nonce of the user
    network: Network
        The network the user belongs to if s/he has already been joined,
        None else

     Methods
    -------
    request(state: State) -> str
        Publish request to blockchain and return hex string of the created
        request
    request_sent() -> bool
        Return True if request has already been published
    is_served(state: State) -> bool
        Return True request has been served
    get_network(state: State) -> Network
        Network this user is a part of
    """

    def __init__(self,
            service: bytes,
            network_size: int,
            user_size: int,
            capabilities: bytes,
            nonce: bytes = None,
        ):

        self.service: bytes = service
        self.network_size: int = network_size
        self.user_size: int = user_size
        self.capabilities: bytes = bytes.fromhex('00') if capabilities == b'' else capabilities
        self.nonce: bytes = nonce
        self.network: Union[Network, None] = None
        self._request_txid = None

    def request(self, state: State = None, simulated: bool = False) -> str:
        """Write this user request into the buffer of the state so that is
        written onto the blockchain.

        :state: State:
            State to add the request to; if None, just create the request (for eval)
        :simulated: bool:
            If True, only simulate (eval).
        :return: Hex string of the created user request"""

        # Define message layout
        layout = UserRequest.LAYOUT
        net_size_bytes = bytes([self.network_size])
        user_size_bytes = bytes([self.user_size])

        # Pad capabilities
        capabilities = bytes.fromhex('00' * (layout['capabilities'] - len(self.capabilities))) + self.capabilities

        # check if all values have correct length
        cond_service = len(self.service) != layout['service']
        cond_net_size = len(net_size_bytes) != layout['network_size']
        cond_user_size = len(user_size_bytes) != layout['user_size']
        cond_capabilities = len(capabilities) != layout['capabilities']
        cond_nonce = len(self.nonce) != layout['nonce']

        # Return error in case this is not the case
        if cond_service or cond_net_size or cond_user_size or cond_capabilities or cond_nonce:
            print("Service: ", self.service, len(self.service), layout['service'], cond_service)
            print("Net Size: ", net_size_bytes, len(net_size_bytes), layout['network_size'], cond_net_size)
            print("User Size: ", user_size_bytes, len(user_size_bytes), layout['user_size'], cond_user_size)
            print("Capabilities: ", capabilities, len(capabilities), layout['capabilities'], cond_capabilities)
            print("Nonce", self.nonce, len(self.nonce), layout['nonce'], cond_nonce)
            raise ValueError('Invalid user request argument(s)')

        # Define payload of request
        request = bytearray()
        request.extend(self.service)
        request.extend(net_size_bytes)
        request.extend(user_size_bytes)
        request.extend(capabilities)
        request.extend(self.nonce)
        # Add the type prefix of a user request
        _add_wrapper(request, UserRequest)

        # Convert request into hex because the blockchain contains hex strings
        request_hex = request.hex()

        # Write request into state buffer
        if not simulated and state is not None:
            state.request_user(self, request_hex)

        return request_hex
        # Tell state to watch for our request
        # state.watch_request(self._request_txid)

    def request_sent(self) -> bool:
        """Return true, if the request has already been sent."""
        return hasattr(self, '_request_txid')

    if not BASIC_MODE:
        # Network dependent functionality does not make any sense in basic mode

        def is_served(self, state: State) -> bool:
            """Return true, if this user is already assigned a NW."""
            if not self.request_sent():
                # If we did not send a request, there is nothing to get served
                return False

            if self.network is None:
                try:
                    self.network = state.pop_served_request(
                        self._request_txid)
                except ValueError:
                    return False
                else:
                    return True
            else:
                return True

        def get_network(self, state: State) -> Network:
            """Return the network this user is assigned to."""
            if not self.is_served(state):
                raise RuntimeError("Request did not get served")
            else:
                return self.network


class Peer:
    """
    Class representing a Peer.

    Attributes
    ----------
    ip_address : ipaddress.ip_address
        IP Address of this peer
    port : int
        Port of this peer
    public_key : bytes
        Public key of this peer
    private_key : bytes
        Private key of this peer
    cont_tx : opreturn.Transaction
        The change address of the transaction this peer used for his/her
        last Ad (I.e. the peer has at least those funds available)
    advertized : bool
        True if the peer Ad is already on blockchain

     Methods
    -------
    advertise(state: State) -> str
        Publish the information about this peer on the blockchain and
        return the created advertisement as hex string
    get_public_key() -> ecdsa.
    Return public key of this peer as ecdsa object.
    get_private_key() -> ecdsa.SigningKey
        Return private key of this peer as ecdsa object.
    public_key_hash() -> str
        Return SHA256 hash of this peers public key padded to 33 byte.
    ready() -> bool
        Return true, if this peer exists in the blockchain.
    get_available_funds() -> float
        Return the funds this peer has currently available
    """

    def __init__(self,
            ip_address: ipaddress.ip_address,
            port: int,
            public_key: bytes,
            private_key: bytes,
            cont_tx: opreturn.Transaction,
            service: bytes = None,
            capabilities: bytes = None,
        ):

        self.direct_pubkey = False  # Prototype does not use D-flag
        self.is_ipv6 = (ip_address.version == 6)
        self.ip_address: ipaddress.ip_address = ip_address
        self.port: int = port
        self.public_key: bytes = public_key
        self.private_key: bytes = private_key
        self.cont_tx: opreturn.Transaction = cont_tx
        self.advertized: bool = False

        if service is None:
            self.service = bytes(PeerAdvertisement.LAYOUT["service"])
        else:
            if len(service) != PeerAdvertisement.LAYOUT["service"]:
                raise ValueError("Service ID has wrong length")
            self.service = service

        if capabilities is None:
            self.capabilities = bytes(PeerAdvertisement.LAYOUT["capabilities"])
        else:
            if len(capabilities) > PeerAdvertisement.LAYOUT["capabilities"]:
                raise ValueError("Capabilities too long")
            self.capabilities = capabilities + bytes([0x00] * (PeerAdvertisement.LAYOUT["capabilities"] - len(capabilities)))

    def get_public_key(self) -> ecdsa.VerifyingKey:
        """"Return public key of this peer as ecdsa object."""
        return ecdsa.VerifyingKey.from_string(self.public_key, curve=ecdsa.SECP256k1)

    def get_private_key(self) -> ecdsa.SigningKey:
        """Return private key of this peer as ecdsa object."""
        return ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)

    def public_key_hash(self) -> bytes:
        """Return SHA256 hash of this peers public key padded to 33 byte."""
        return hashlib.sha256(self.public_key).digest().zfill(33)

    def advertise(self, state: State = None, simulated: bool = False) -> str:
        """Publish the information about this peer in the blockchain and
        return the created advertisement as hex string.

        :state: State :
            Write the ad into this state's buffer; if None, just create advertisement based on dummy data (eval)
        :simulated: bool:
            If set, just work on dummy data (eval)
        :return: str :
            Peer Ad as hex string
        """
        if state is None and not simulated:
            raise ValueError("If we don't simulate peer advertisements, I need a state to work with!")
        if EVAL:
            self.cont_tx = None
        else:
            if not is_valid_utxo(self.cont_tx):
                raise ValueError("Peer does not have spendable coins.")

        # Define layout of peer advertisement
        layout = PeerAdvertisement.LAYOUT
        
        ad_flags = bytes([((self.direct_pubkey << 1) | self.is_ipv6) << 6])
        ad_pubkey = self.public_key_hash()
        if self.ip_address.version == 4:
            ad_ip = self.ip_address.packed + bytes([0x00] * 12)
        else:
            ad_ip = self.ip_address.packed
        ad_port = int_to_bytes(self.port)
        ad_service = self.service
        ad_capabilities = self.capabilities

        # Check that length values match the service demands
        cond_flags = len(ad_flags) != layout['flags']
        cond_pubkey = len(ad_pubkey) != layout['pubkey']
        cond_ip = len(ad_ip) != layout['ip']
        cond_port = len(ad_port) != layout['port']
        cond_service = len(ad_service) != layout['service']
        cond_capabilities = len(ad_capabilities) != layout['capabilities']

        # otherwise throw error
        if cond_flags or cond_ip or cond_port or cond_pubkey or cond_service or cond_capabilities:
            print('Flags: {:08b}'.format(((self.direct_pubkey << 1) | self.is_ipv6) << 6))
            print('Direct Pubkey: {}'.format(self.direct_pubkey))
            print('Is IPv6: {}'.format(self.is_ipv6))
            print('Flags: {:08b}'.format(((True << 1) | True) << 6))
            print('cond_flags: {}'.format(cond_flags))
            print('Flags: {}'.format(ad_flags))
            print('cond_pubkey: {}'.format(cond_pubkey))
            print('cond_ip: {}'.format(cond_ip))
            print('cond_port: {}'.format(cond_port))
            print('cond_service: {}'.format(cond_service))
            print('cond_capabilities: {}'.format(cond_capabilities))
            raise ValueError('Invalid peer ad argument(s)')

        # Compute a valid PoW for this transaction
        if not simulated:
            block_height = AuthServiceProxy(
                "http://%s:%s@127.0.0.1:%s" % (
                    State.RPC_USER,
                    State.RPC_PASSWORD,
                    State.PORT
                )
            ).getblockcount()
            merkle = _get_last_merkle_root_before(
                block_height + 1,
                state.l_s,
                state.fuzzy
            )
        else:
            # We use a random merkleroothash
            merkle = hashlib.sha256(getrandbits(256).to_bytes(32, 'big')).digest().hex()
        # +1 because the transaction will be at earliest mined into the next
        # block
        if EVAL:
            powork = pow.calculate_powork(ad_pubkey, merkle, 0)
        else:
            powork = pow.calculate_powork(ad_pubkey, merkle)

        # Add payload to advertisement
        peer_ad = bytearray()
        peer_ad.extend(ad_flags)
        peer_ad.extend(ad_pubkey)
        peer_ad.extend(ad_ip)
        peer_ad.extend(ad_port)
        peer_ad.extend(ad_service)
        peer_ad.extend(ad_capabilities)
        peer_ad.extend(powork)

        # Add type information
        # print("Length flags: {}".format(len(ad_flags)))
        # print("Length pubkey: {}".format(len(ad_pubkey)))
        # print("Length IP: {}".format(len(ad_ip)))
        # print("Length Port: {}".format(len(ad_port)))
        # print("Length Service: {}".format(len(ad_service)))
        # print("Length capabilities: {}".format(len(ad_capabilities)))
        # print("Length Nonce: {}".format(len(powork)))

        # print('Length peer ad w/o header: {}'.format(len(peer_ad)))
        _add_wrapper(peer_ad, PeerAdvertisement)
        # print('Length peer ad: {}'.format(len(peer_ad)))

        # Convert to hex for blockchain
        peer_ad_hex = peer_ad.hex()

        # Write advertisement into state's buffer
        if not simulated:
            state.advertise_peer(self, peer_ad_hex)
        self.advertized = True
        return peer_ad_hex

    def ready(self, state: State) -> bool:
        """Return true, if this peer exists on the blockchain."""
        pubkey_hex = self.public_key_hash().hex()
        return state.exists_peer(pubkey_hex)

    def get_available_funds(self) -> float:
        """Return the funds this peer has currently available"""
        return AuthServiceProxy(
            "http://%s:%s@127.0.0.1:%s" % (
                State.RPC_USER, State.RPC_PASSWORD, State.PORT)
        ).gettxout(self.cont_tx[0], self.cont_tx[1])['value']
