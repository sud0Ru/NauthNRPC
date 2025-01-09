from impacket.dcerpc.v5.nrpc import NULL, MSRPC_UUID_NRPC, hDsrGetDcNameEx, NetrEnumerateTrustedDomainsEx, \
    DsrGetDcNameEx2, checkNullString
from impacket.dcerpc.v5 import transport, epm
from impacket.uuid import bin_to_string, string_to_bin

from constants import DcNameEx_flag_mapping, trust_flag_mapping, trust_type_mapping, trust_attribute_mapping

import sys
import struct
import argparse


def args_parser():
    parser = argparse.ArgumentParser(add_help=True, description="NAuthNRPC tool to access MS-NRPC interface methods "
                                                                "under auth level=1."
                                                                "This tool allows you to enumerate domain "
                                                                "information, trusted domains, user and computer "
                                                                "accounts without authentication.")
    parser.add_argument('-t', '--target', action='store', help='Domain controller IP address')
    parser.add_argument('-u', '--usersfile', action='store', help='File that contains user accounts', required=False)
    parser.add_argument('-c', '--computersfile', action='store', help='File that contains computer accounts',
                        required=False)
    parser.add_argument('-v', '--verbose', action='store_true', help='Print all accounts (default: only existing accounts)')

    return parser


def print_banner():
    banner = """\n\033[1mNAuthNRPC Tool By Haidar Kabibo - Kaspersky Security Services 2024\033[0m\n"""
    print(banner)


def hNetrEnumerateTrustedDomainsEx(dce, serverName):
    """
    Helper function for NetrEnumerateTrustedDomainsEx call
    """
    request = NetrEnumerateTrustedDomainsEx()
    request['ServerName'] = checkNullString(serverName)
    return dce.request(request)


def hDsrGetDcNameEx2(dce, computerName, accountName, allowableAccountControlBits, domainName, domainGuid, siteName,
                     flags):
    """
    Rewrite helper fucntion for DsrGetDcNameEx2 call to prevent rasing exceptions by impacket 
    """
    request = DsrGetDcNameEx2()
    request['ComputerName'] = checkNullString(computerName)
    request['AccountName'] = checkNullString(accountName)
    request['AllowableAccountControlBits'] = allowableAccountControlBits
    request['DomainName'] = checkNullString(domainName)
    request['DomainGuid'] = domainGuid
    request['SiteName'] = checkNullString(siteName)
    request['Flags'] = flags
    return dce.request(request, checkError=False)


class NAuthNRPC:

    def __init__(self, ip, users_file=None, computers_file=None, verbose=False):
        self.output = None
        self.domain_info = None
        self.dce = None
        self.bind = None
        # Flag to indicate if the domain info is retrieved successfully
        self.domain_info_flag = False
        self.verbose = verbose
        self.address = ip
        if users_file is not None:
            try:
                with open(usersfile, 'r') as users:
                    self.users = [username.strip() for username in users.readlines()]
            except Exception as e:
                print(f"Couldn't open users file {usersfile}: {e} ")
                sys.exit(1)
        else:
            self.users = None
        if computers_file is not None:
            try:
                with open(computersfile, 'r') as computers:
                    self.computers = [computer.strip() for computer in computers.readlines()]
            except Exception as e:
                print(f"Couldn't open computers file {computersfile}: {e}")
                sys.exit(1)
        else:
            self.computers = None

    def get_string_binding(self):
        """
        Use endpoint mapper service to get the string binding of MS-NRPC
        """
        self.bind = epm.hept_map(self.address, MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')

    def rpc_connector(self):
        """
        Function to connect to MS-NRPC endpoint
        """
        rpc_transport = transport.DCERPCTransportFactory(self.bind)
        dce = rpc_transport.get_dce_rpc()
        dce.set_auth_level(1)
        dce.connect()
        dce.bind(MSRPC_UUID_NRPC)
        self.dce = dce

    def domain_info_retriever(self):
        """
        Get domain info and trusted domains from the remote DC
        """
        domain_info = dict()
        domain_info['trusted_domains'] = dict()
        resp = hDsrGetDcNameEx(self.dce, '', '', NULL, NULL, 0)
        dc_info = resp['DomainControllerInfo']
        for i in vars(dc_info)['fields'].keys():
            domain_info[i] = dc_info[i]

        resp = hNetrEnumerateTrustedDomainsEx(self.dce, '')
        trust_info = resp['Domains']
        for i in vars(trust_info)['fields'].keys():
            domain_info['trusted_domains'][i] = trust_info[i]

        self.domain_info = domain_info

    def domain_info_parser(self):
        """
        Parse the DC response in order to print it later
        """
        output = {"DC Name": self.domain_info['DomainControllerName'][2:],
                  "DC IP": self.domain_info['DomainControllerAddress'][2:],
                  "Domain GUID": bin_to_string(self.domain_info['DomainGuid']),
                  "Domain Name": self.domain_info['DomainName'], 
                  "Forest Name": self.domain_info['DnsForestName'],
                  "DC Site Name": self.domain_info['DcSiteName'],
                  "Client Site Name": self.domain_info['ClientSiteName']}
        flags = list()
        for flag in DcNameEx_flag_mapping.keys():
            if int(hex(self.domain_info['Flags']), 16) & flag:
                flags.append(DcNameEx_flag_mapping[flag])
        output["Domain Flags"] = " | ".join(flags)
        output['Trusted Domains'] = {}
        output['Trusted Domains'] = self.trusted_domains_parser()

        self.output = output

    def trusted_domains_parser(self):
        output = {}
        dcount = self.domain_info['trusted_domains']['DomainCount']
        domains = self.domain_info['trusted_domains']['Domains']
        for i in range(0, dcount):
            output[i] = dict()
            for domain in vars(domains[i])['fields'].keys():
                if domain == 'DomainSid':
                    if domains[i]['DomainSid'] == b'':
                        output[i]['Domain SID'] = ''
                    else:
                        rev = domains[i]['DomainSid']['Revision']
                        iden = struct.unpack('>Q', b'\x00\x00' + domains[i]['DomainSid']['IdentifierAuthority'])[0]
                        subauth = '-'.join(map(str, domains[i]['DomainSid']['SubAuthority']))
                        sid = f"s-{rev}-{iden}-{subauth}"
                        output[i]['Domain SID'] = sid

                elif domain == 'NetbiosDomainName':
                    output[i]['NetBios Domain Name'] = domains[i][domain]
                elif domain == 'DnsDomainName':
                    output[i]['DNS Domain Name'] = domains[i][domain]
                elif domain == 'Flags':
                    flags = list()
                    for flag in trust_flag_mapping.keys():
                        if int(hex(domains[i]['Flags']), 16) & flag:
                            flags.append(trust_flag_mapping[flag])
                    output[i]["Flags"] = " | ".join(flags)

                elif domain == 'ParentIndex':
                    output[i]["Parent Index"] = domains[i][domain]
                elif domain == 'TrustType':
                    if domains[i][domain] in trust_type_mapping:
                        output[i]["Trust Type"] = trust_type_mapping[domains[i][domain]]
                    else:
                        output[i]["Trust Type"] = domains[i][domain]
                elif domain == 'TrustAttributes':
                    if domains[i][domain] in trust_attribute_mapping:
                        output[i]["Trust Attributes"] = trust_attribute_mapping[domains[i][domain]]
                    else:
                        output[i]["Trust Attributes"] = domains[i][domain]
                if domain == 'DomainGuid':
                    output[i]['Domain GUID'] = bin_to_string(domains[i][domain])

        return output

    def print_dom_info(self):
        domain_info_printed = False
        for key, value in self.output.items():
            if key == "Trusted Domains":
                if domain_info_printed:
                    print("\n[*] Trusted Domains Information\n" + "-" * 30)
                else:
                    print("[*] Trusted Domains Information\n" + "-" * 30)
                for subkey, subvalue in value.items():
                    print(f"[*] Trusted Domain number {subkey}")
                    for ssubkey, ssubvalue in subvalue.items():
                        if not bool(ssubvalue):
                            ssubvalue = "Not Available"
                        print(f"    \u2022 {ssubkey}: {ssubvalue}")
            else:
                if not domain_info_printed:
                    print("[*] Domain Information\n" + "-" * 30)
                    domain_info_printed = True
                    if not bool(value):
                        value = "Not Available"
                print(f"[*] {key}: {value}")

    def domain_users_enumerator(self):
        """
        Main function used for user enumeration. If we already have domain info, 
        we pass it immediately to hDsrGetDcNameEx2 function. However, this function can also 
        work with NULL values for almost all its parameters.
        """
        print("\n[*] User Accounts Enumeration\n" + "-" * 30)
        for username in self.users:
            if self.domain_info_flag:
                response = hDsrGetDcNameEx2(self.dce,
                                            self.output['DC Name'].split(".")[0],
                                            username, 0x200, self.output["Domain Name"],
                                            string_to_bin(self.output["Domain GUID"]),
                                            self.output["DC Site Name"],
                                            0x40020200)
            else:
                response = hDsrGetDcNameEx2(self.dce, NULL, username, 0x200, NULL, NULL, NULL, 0)

            if response is not None and response["ErrorCode"] == 0:
                print(f"[+] user {username} exists.")
            elif self.verbose:
                print(f"[-] user {username} does not exist")

    def computer_accounts_enumerator(self):
        """
        The same function as above, but it's used for enumerating computer accounts.
        """
        print("\n[*] Computer Accounts Enumeration\n" + "-" * 30)
        for computer_account in self.computers:
            if computer_account[-1] != '$':
                computer_account = computer_account + "$"
                if self.domain_info_flag:
                    response = hDsrGetDcNameEx2(self.dce,
                                                self.output['DC Name'].split(".")[0],
                                                computer_account,
                                                0x1000,
                                                self.output["Domain Name"],
                                                string_to_bin(self.output["Domain GUID"]),
                                                self.output["DC Site Name"],
                                                0x40020200)
                else:
                    response = hDsrGetDcNameEx2(self.dce, NULL, computer_account, 0x1000, NULL, NULL, NULL, 0)

                if response is not None and response["ErrorCode"] == 0:
                    print(f"[+] computer account {computer_account} exists.")
                elif self.verbose:
                    print(f"[-] user {computer_account} does not exist")

    def run(self):
        try:
            self.get_string_binding()
        except Exception as e:
            print(f"Couldn't get endpoint for MS-NRPC interface:{e}")
            return
        try:
            self.rpc_connector()
        except Exception as e:
            print(f"Couldn't bind MS-NRPC interface: {e}")
            return
        try:
            self.domain_info_retriever()
            self.dce.disconnect()
            self.domain_info_flag = True
            self.dce = None
        except Exception as e:
            if self.dce is not None:
                self.dce.disconnect()
                self.dce = None
            print(f"Couldn't get domain information: {e}")
        try:
            if self.domain_info_flag:
                self.domain_info_parser()
                self.print_dom_info()
        except Exception as e:
            print(f"Couldn't parse domain information: {e}")

        try:
            if self.users is not None:
                self.rpc_connector()
                self.domain_users_enumerator()
                self.dce.disconnect()
                self.dce = None
        except Exception as e:
            if self.dce is not None:
                self.dce.disconnect()
                self.dce = None
            print(f"Couldn't enumerate user accounts: {e}")

        try:
            if self.computers is not None:
                self.rpc_connector()
                self.computer_accounts_enumerator()
                self.dce.disconnect()
                self.dce = None
        except Exception as e:
            if self.dce is not None:
                self.dce.disconnect()
            print(f"Couldn't enumerate computer accounts: {e}")


if __name__ == '__main__':
    print_banner()
    parser = args_parser()
    options = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    target = options.target
    usersfile = options.usersfile
    computersfile = options.computersfile
    verbose = options.verbose
    nauth = NAuthNRPC(target, usersfile, computersfile, verbose)
    nauth.run()
